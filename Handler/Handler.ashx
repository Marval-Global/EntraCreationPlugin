<%@ WebHandler Language = "C#" Class="Handler" %>

using System;

using System.IO;
using System.Net;
using System.Xml;
using System.Linq;
using System.Xml.Linq;
using Newtonsoft.Json.Linq;
using System.Reflection;
using System.Xml.Serialization;
using System.Collections;
using System.Net.Http.Headers;

using System.Collections.Generic;
using System.Text;
using MarvalSoftware.ServiceDesk.ServiceDelivery.AvailabilityManagement;
using System.Threading;
using System.Threading.Tasks;
using Serilog;
using System.Web.Script.Serialization;
using MarvalSoftware.Data.ServiceDesk;
using MarvalSoftware.Data.ServiceDesk.Rules;
using System.Web;
using MarvalSoftware.Rules;
using MarvalSoftware.ServiceDesk.Facade;
using MarvalSoftware.Predicates;
using MarvalSoftware.ServiceDesk.Facade.Rules.RuleActions;
using MarvalSoftware.DataTransferObjects.IntegrationMessages;
using MarvalSoftware.ServiceDesk.Facade.Rules.RuleObjects;
using MarvalSoftware.DataTransferObjects;
using MarvalSoftware.DataTransferObjects.Rules;
using MarvalSoftware;
using MarvalSoftware.UI.WebUI.ServiceDesk.RFP.Plugins;
using MarvalSoftware.UI.WebUI.ServiceDesk.RFP.Forms;
using System.Net.Http;
using Newtonsoft.Json;
using MarvalSoftware.Data;
public class Handler : PluginHandler
{
    private ServiceDeskFacade serviceDeskFacade = new ServiceDeskFacade();
    private RuleSetBroker rulesetBroker = new RuleSetBroker();
    private ActionMessageBroker actionMessageCreate = new ActionMessageBroker();
    private static readonly HttpClient httpClient = new HttpClient();

    public class State
    {
        public int Id { get; set; }
        public int StatusId { get; set; }
        public string Name { get; set; }
        public List<int> NextWorkflowStatusIds { get; set; }
    }
    public class EntityData
    {
        public int id { get; set; }
        public string name { get; set; }
        public List<State> states { get; set; }
    }
    private string MSMBaseUrl
    {
        get
        {
            return "https://" + HttpContext.Current.Request.Url.Host + MarvalSoftware.UI.WebUI.ServiceDesk.WebHelper.ApplicationPath;
        }
    }

    public class Entity
    {
        public EntityData data { get; set; }
    }

    public class WorkflowReadResponse
    {
        public EntityData data { get; set; }
    }

    private class RequestModel
    {
        public string FirstName { get; set; }
        public string FamilyName { get; set; }
        public string FullName { get; set; }
        [JsonProperty("Name")] public string Name { get; set; }
        public string APITOKEN { get; set; }
        [JsonProperty("Email Address")] public string EmailAddress { get; set; }
        public string PreferredEmailAddress { get; set; }
        public string ContactAddress { get; set; }
        public string ApproverEmail { get; set; }
        public string RequestNumber { get; set; }
    }
    public class WorkflowInfo
    {
        public int WorkflowId { get; set; }
        public int StatusId { get; set; }
    }
    public class RequestData
    {
        public string Message { get; set; }
        public string PhoneTo { get; set; }
        public string action { get; set; }
        public string encryptString { get; set; }
        public string actionMessageText { get; set; }

        public string actionMessageURL { get; set; }
        public int actionMessageId { get; set; }
        public int WorkflowId { get; set; }

        public int WorkflowStatusId { get; set; }

        public string email { get; set; }
        public string mailNickname { get; set; }
        public string Firstname { get; set; }
        public string Lastname { get; set; }
        public string fullName { get; set; }
        public string requestId { get; set; }

    }

    private class TokenResponse
    {
        public string token_type { get; set; }
        public int expires_in { get; set; }
        public string access_token { get; set; }
    }

    private static string GeneratePassword(int length)
    {
        const string chars = "!@#$%^&*0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz";
        var rng = new Random();
        return new string(Enumerable
            .Range(0, length)
            .Select(_ => chars[rng.Next(chars.Length)])
            .ToArray());
    }


    private string EntraIDAppicationString { get { return this.GlobalSettings["@@EntraIDAppicationString"]; } }
    private string Settings { get { return this.GlobalSettings["@@Settings"]; } }
    private string ApplicationSecret { get { return this.GlobalSettings["@@ApplicationSecret"]; } }
    private string EntraCreationAuthToken { get { return this.GlobalSettings["@@EntraCreationAuthToken"]; } }
    private string EntraCreationFromPhone { get { return this.GlobalSettings["@@EntraCreationFromPhone"]; } }


    private string MarvalAPIKey { get { return this.GlobalSettings["@@MarvalAPIKey"]; } }

    public override bool IsReusable { get { return false; } }


    private string PostRequest(string url, string data, string credentials = "", string contentType = "application/json")
    {
        try
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = "POST";
            request.ContentType = contentType;
            request.Headers.Add("Authorization", credentials);
            Log.Information("Posting to address " + url);
            Log.Information("Posting with credentials " + credentials);
            Log.Information("Posting with data " + data);
            if (contentType.Equals("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
            {
                data = System.Web.HttpUtility.UrlEncode(data);
            }

            using (StreamWriter writer = new StreamWriter(request.GetRequestStream()))
            {
                writer.Write(data);
            }

            using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
            {
                using (StreamReader reader = new StreamReader(response.GetResponseStream()))
                {
                    return reader.ReadToEnd();
                }
            }
        }
        catch (WebException webEx)
        {
            if (webEx.Response != null)
            {
                using (var errorResponse = (HttpWebResponse)webEx.Response)
                {
                    using (var reader = new StreamReader(errorResponse.GetResponseStream()))
                    {
                        string errorText = reader.ReadToEnd();
                        Log.Information("Have error as " + errorText);
                        return errorText;
                    }
                }
            }

            return webEx.Message;
        }
        catch (Exception ex)
        {
            return ex.ToString();
        }
    }
    private string PostRequest2(string url, HttpContent data, string credentials = "", string contentType = "application/json")
    {
        try
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = "POST";
            request.ContentType = contentType;
            request.Headers.Add("Authorization", credentials);
            Log.Information("Posting to address" + url);
            Log.Information("Posting with credentials " + credentials);
            Log.Information("Posting with data " + data);

            using (Stream requestStream = request.GetRequestStream())
            {
                data.CopyToAsync(requestStream).GetAwaiter().GetResult();
            }

            using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
            using (StreamReader reader = new StreamReader(response.GetResponseStream()))
            {
                return reader.ReadToEnd();
            }
        }
        catch (WebException webEx)
        {
            if (webEx.Response != null)
            {
                using (var errorResponse = (HttpWebResponse)webEx.Response)
                {
                    using (var reader = new StreamReader(errorResponse.GetResponseStream()))
                    {
                        string errorText = reader.ReadToEnd();
                        return errorText;
                    }
                }
            }

            return webEx.Message;
        }
        catch (Exception ex)
        {
            return ex.ToString();
        }
    }

    private string GetRequest(string url, string credentials, string contentType = "application/json")
    {
        try
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = "GET";
            request.ContentType = contentType;
            request.Headers.Add("Authorization", credentials);
            Log.Information("Posting to address " + url);
            Log.Information("Posting with credentials " + credentials);
            //  Log.Information("Posting with data " + data);

            // using (Stream requestStream = request.GetRequestStream())
            // {
            //     data.CopyToAsync(requestStream).GetAwaiter().GetResult();
            // }

            using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
            using (StreamReader reader = new StreamReader(response.GetResponseStream()))
            {
                return reader.ReadToEnd();
            }
        }
        catch (WebException webEx)
        {
            if (webEx.Response != null)
            {
                using (var errorResponse = (HttpWebResponse)webEx.Response)
                {
                    using (var reader = new StreamReader(errorResponse.GetResponseStream()))
                    {
                        string errorText = reader.ReadToEnd();
                        return errorText;
                    }
                }
            }

            return webEx.Message;
        }
        catch (Exception ex)
        {
            return ex.ToString();
        }
    }

    public override void HandleRequest(HttpContext context)
    {
        var param = context.Request.HttpMethod;
        var browserObject = context.Request.Browser;

        // MsmRequestNo = !string.IsNullOrWhiteSpace(context.Request.Params["requestNumber"]) ? int.Parse(context.Request.Params["requestNumber"]) : 0;

        switch (param)
        {
            case "GET":
                var getParamVal = context.Request.Params["endpoint"] ?? string.Empty;
                var getUrlEndpoint = context.Request.Params["urlEndpoint"] ?? string.Empty;
                //   var reqData = context.Request.Params["data"] ?? string.Empty;

                if (getParamVal == "getSnippet")
                {
                    byte[] binaryData = Convert.FromBase64String(getUrlEndpoint);
                    string decodedString = System.Text.Encoding.UTF8.GetString(binaryData);
                    context.Response.Write("{ \"response\": \"Retrieving snippet " + decodedString + "\" } ");
                }
                else if (getParamVal == "testPlugin")
                {
                    Log.Information("Decrypting string " + EntraIDAppicationString);
                    string decryptString = AesEncryptionHelper.Instance.Decrypt(EntraIDAppicationString);
                    Log.Information("Have decrypted string as " + decryptString);
                    string[] parts = decryptString.Split(new[] { '^' }, 3, StringSplitOptions.None);
                    string tenantId = parts.Length > 0 ? parts[0] : null;
                    string appId = parts.Length > 1 ? parts[1] : null;
                    string clientSecret = parts.Length > 2 ? parts[2] : null;
                    var accessToken = GetGraphTokenAsync(appId, clientSecret, tenantId);
                    var url = "https://graph.microsoft.com/v1.0/applications/" + appId + "?$select=displayName,requiredResourceAccess";

                    JObject result;
                    try
                    {
                        result = JObject.Parse(accessToken);
                        string BearerToken = "Bearer " + result["access_token"];
                        var response2 = GetRequest(url, BearerToken);
                        Log.Information("Result is " + response2);
                    }
                    catch (JsonReaderException)
                    {
                        context.Response.StatusCode = 502;
                        context.Response.Write(JsonConvert.SerializeObject(new
                        {
                            error = "Invalid response from token endpoint for appID " + appId
                        }));
                        return;
                    }
                    JToken errorDesc;
                    string error_result = (string)result["error_description"] ?? "";
                    Log.Information("This is an error description " + error_result + " for appID " + appId);
                    if (!string.IsNullOrEmpty(error_result))
                    {
                        var payload = new { error = error_result, appID = appId };
                        context.Response.ContentType = "application/json; charset=utf-8";
                        context.Response.Write(JsonConvert.SerializeObject(payload));
                    }
                    else
                    {
                        context.Response.StatusCode = 200;
                        context.Response.Write(JsonConvert.SerializeObject(new
                        {
                            success = true,
                            appID = appId

                        }));
                    }

                    Log.Information("Have access token as " + accessToken);
                    //   context.Response.Write(accessToken);
                }
                else
                {
                    Log.Information("No valid GET parameter requested");
                    context.Response.Write("No valid GET parameter requested");
                }
                break;
            case "POST":

                if (!context.Request.ContentType.StartsWith("application/json", StringComparison.OrdinalIgnoreCase))
                {
                    context.Response.StatusCode = 415;
                    context.Response.End();
                    return;
                }
                string json;
                using (var reader = new StreamReader(context.Request.InputStream))
                {
                    json = reader.ReadToEnd();
                }

                RequestData data;
                try
                {
                    data = JsonConvert.DeserializeObject<RequestData>(json);
                }
                catch (JsonException)
                {
                    context.Response.StatusCode = 400; // Bad Request
                    context.Response.Write("Invalid JSON");
                    context.Response.End();
                    return;
                }
                var action = data.action;
                var actionMessageText = data.actionMessageText;
                var encryptString = data.encryptString;
                var email = data.email;
                var WorkflowId = data.WorkflowId;
                var WorkflowStatusId = data.WorkflowStatusId;
                var actionMessageURL = data.actionMessageURL;
                var actionMessageId = data.actionMessageId;
                var mailNickname = data.mailNickname;
                var Firstname = data.Firstname;
                var Lastname = data.Lastname;
                var fullName = data.fullName;
                var requestId = data.requestId;

                if (action == "createTeams")
                {
                    var attributeTypes = new RequestAttributeTypeBroker();
                    AttributeTypeInfo[] attributes = attributeTypes.GetAllAttributeTypes(false, false);
                    string allattributes = string.Join(Environment.NewLine, attributes.Select(w => w.Name.ToString()));
                    Log.Information("Returning " + allattributes);
                    string jsonAttributes = JsonConvert.SerializeObject(attributes);
                    context.Response.Write(jsonAttributes);
                }
                else if (action == "moveStatus")
                {

                    context.Response.Write("{ \"response\": \"Moved Status Successfully" + "\" } ");

                }
                else if (action == "getWorkflows")
                {

                    var workflowService = new AvailabilityManagementFacade();
                    IdentifiedElement[] workflows = workflowService.GetAllWorkflowsView();
                    string jsonWorkflows = JsonConvert.SerializeObject(workflows);
                    context.Response.Write(jsonWorkflows);

                }
                else if (action == "getWorkflowStatuses")
                {

                    var workflowStatusService = new StatusBroker();
                    IdentifiedElement[] workflows = workflowStatusService.GetAllStatusesView();
                    string jsonWorkflows = JsonConvert.SerializeObject(workflows);
                    context.Response.Write(jsonWorkflows);

                }
                else if (action == "getRequestAtributes")
                {

                    var attributeTypes = new RequestAttributeTypeBroker();
                    AttributeTypeInfo[] attributes = attributeTypes.GetAllAttributeTypeNames(false, false);
                    string jsonAttributes = JsonConvert.SerializeObject(attributes);
                    Log.Information("Returning " + jsonAttributes);
                    context.Response.Write(jsonAttributes);
                }
                else if (action == "createActionRule")
                {
                    var webhookMessage = new SendWebhookMessageBody
                    {
                        ActionMessageIdentifier = actionMessageId,
                        ActionMessageName = "Entra Integration Message - Automated",
                        AuthenticationSessionId = null,
                        Body = "",
                        EntityIdentifier = 0,
                        RelatedEntityType = NotificationRelatedEntityTypes.Invalid,
                        Headers = new[]
                    {
                    new SendWebhookMessageBody.Header(1, "Content-Type", "application/json")

                   },
                        QueryString = "",
                        Url = actionMessageURL,
                        Verb = SendWebhookMessageBody.Verbs.Post,
                        AuthenticationType = MarvalSoftware.DataTransferObjects.IntegrationMessages.SendWebhookMessageBody.AuthenticationTypes.None,
                        UseBasicAuthentication = false,
                        Username = "",


                    };

                    // MarvalSoftware.DataTransferObjects.IntegrationMessages.SendWebhookMessageBody

                    ReferencedEntityInfo[] referencedEntities = { };
                    var groupPredicate = new GroupPredicate();
                    // groupPredicate.Predicates.Add(new MemberPredicate()
                    // {
                    //     Name = "IsNew",
                    //     Operator = MemberPredicate.Operators.Equals,
                    //     Value = true
                    // });
                    groupPredicate.Predicates.Add(new MemberPredicate()
                    {
                        Name = "Workflow",
                        Operator = MemberPredicate.Operators.Equals,
                        Value = WorkflowId
                    });
                    groupPredicate.Predicates.Add(new MemberPredicate()
                    {
                        Name = "Status",
                        Operator = MemberPredicate.Operators.Equals,
                        Value = WorkflowStatusId
                    });

                    //   groupPredicate.Predicates.Add(new MemberPredicate()
                    //  {
                    //      Name = "IsMajorIncident",
                    //      Operator = MemberPredicate.Operators.Equals,
                    //      Value = true
                    //  });

                     int ruleSetIds = 0;
                    using (var dataGrunt = new DataGrunt())
                    {
                        using (var dataReader = dataGrunt.ExecuteReader("ruleSet_getRuleSetIds", new DataGrunt.DataGruntParameter("ruleSetType", 5)))
                        {
                            var ruleSetIdOrdinal = dataReader.GetOrdinal("ruleSetId");
                            while (dataReader.Read())
                            {
                                ruleSetIds = dataReader.GetInt32(ruleSetIdOrdinal);
                               
                            }
                        }
                    }



                    this.serviceDeskFacade.PersistRule(new MarvalSoftware.Rules.Rule()
                    {
                        Name = "Entra Action Rule - Automated",
                        Predicate = groupPredicate,
                        PredicateSummary = "",
                        Actions = new List<IRuleAction>() {
                        new SendWebhookRuleAction
                              {
                                Predicate = null,
                                Value = webhookMessage
                              }
                       },
                        ActionsSummary = "Web-hook to URL http://test.com with Body TestRequestActionMessage including Headers Authorization: TestingAuth,Content-Type: application/json using Verb Post",
                        IsActive = true
                    }, ruleSetIds, referencedEntities, "RequestClassificationFilter");

                    context.Response.Write("{ \"response\": \"Installed Action Rule Successfully" + "\" } ");
                }
                else if (action == "encrypt")
                {
                    var stringencHelper = AesEncryptionHelper.Instance.Encrypt(encryptString);
                    context.Response.Write(stringencHelper);
                }
                else if (action == "createActionMessage")
                {
                    this.actionMessageCreate.Persist(new MarvalSoftware.ServiceDesk.ActionMessage()
                    {
                        Name = "Entra Integration Message - Automated",
                        IsHtml = false,
                        EntityType = NotificationRelatedEntityTypes.Request,
                        Identifier = 0,
                        // IsActive = true,
                        Content = actionMessageText
                    });
                    context.Response.Write("{ \"response\": \"Installed Action Message Successfully" + "\" } ");
                }
                else if (action == "EntraCreation")
                {
                    try
                    {
                        string decryptString = AesEncryptionHelper.Instance.Decrypt(EntraIDAppicationString);
                        string[] parts = decryptString.Split(new[] { '^' }, 3, StringSplitOptions.None);
                        string tenantId = parts.Length > 0 ? parts[0] : null;
                        string appId = parts.Length > 1 ? parts[1] : null;
                        string clientSecret = parts.Length > 2 ? parts[2] : null;
                        var accessToken = GetGraphTokenAsync(appId, clientSecret, tenantId);
                        Log.Information("Have access token as " + accessToken);
                        var graphClient = new HttpClient();
                        graphClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

                        var password = GeneratePassword(12);

                        var userPayload = new
                        {
                            accountEnabled = true,
                            displayName = Firstname + " " + Lastname,
                            mailNickname = Firstname + Lastname,
                            givenName = Firstname,
                            surname = Lastname,
                            userPrincipalName = email,
                            passwordProfile = new
                            {
                                forceChangePasswordNextSignIn = true,
                                password = password
                            }
                        };

                        var url = "https://graph.microsoft.com/v1.0/users";
                        JObject result = JObject.Parse(accessToken);
                        string BearerToken = "Bearer " + result["access_token"];
                        var createResp = PostRequest(url, JsonConvert.SerializeObject(userPayload), BearerToken);
                        var jsonResp = JObject.Parse(createResp);
                        Log.Information("EntraCreation returned " + jsonResp);
                        string idToken = jsonResp["id"].Value<string>();
                        JToken err = jsonResp["error"];
                        string errorMsg = "";
                        // var errorMsg  = jsonResp["error"]?["message"]?.ToString() ?? string.Empty;
                        var deserialized = JsonConvert.DeserializeObject<Dictionary<string, List<Dictionary<string, string>>>>(Settings);
                        var list = deserialized["settings"];
                        string failureStatus = list[1]["notsuccess"];
                        string successStatus = list[0]["success"];
                        int requestIdInt = 0;
                        Log.Information("Trying to parse requestId as " + requestId);
                        int.TryParse(requestId, out requestIdInt);
                        if (err != null && err["message"] != null)
                        {
                            errorMsg = err["message"].Value<string>();
                            Log.Information("EntraCreation returned an error: " + errorMsg);

                            MoveMSMStatus(requestIdInt, failureStatus);
                            AddMsmNote(requestIdInt, "EntraCreation returned an error: " + errorMsg);
                        }
                        else
                        {
                            Log.Information("No error message in the response.");

                            MoveMSMStatus(requestIdInt, successStatus);
                            AddMsmNote(requestIdInt, "Created user successfully with ObjectId: " + idToken);
                        }
                       
                        context.Response.Write(createResp);
                    }
                    catch (Exception ex)
                    {
                        context.Response.StatusCode = 400;
                        Log.Information("Exception is " + ex);
                        var deserialized = JsonConvert.DeserializeObject<Dictionary<string, List<Dictionary<string, string>>>>(Settings);
                        Log.Information("Have settings as " + Settings);
                        var list = deserialized["settings"];
                        Log.Information("Have item as " + list[0]);
                        string failureStatus = list[1]["notsuccess"];
                        int requestIdInt = 0;
                        int.TryParse(requestId, out requestIdInt);
                        MoveMSMStatus(requestIdInt, failureStatus);
                        // context.Response.ContentType = "application/json";
                        context.Response.ContentType = "text/plain";
                        context.Response.Write(ex.ToString());
                    }
                }
                else
                {
                    Log.Information("No valid POST parameter requested");
                    context.Response.Write("No valid POST parameter requested");
                }
                break;
        }
    }

    private string GetGraphTokenAsync(string clientId, string clientSecret, string tenantId)
    {
        var form = new Dictionary<string, string>();
        form.Add("grant_type", "client_credentials");
        form.Add("scope", "https://graph.microsoft.com/.default");
        form.Add("client_id", clientId);
        form.Add("client_secret", clientSecret);
        var Formcontent = new FormUrlEncodedContent(form);
        var url = "https://login.microsoftonline.com/" + tenantId + "/oauth2/v2.0/token";
        var response = PostRequest2(url, Formcontent, "", "application/x-www-form-urlencoded");

        return response;
    }

    private void MoveMSMStatus(int requestId, string targetStateName)
    {

        Log.Information("Have targetStateName as " + targetStateName);
        Log.Information("Have string to deserialise as " + Settings);



        List<int> MarvalIds = new List<int>();
        var workflowInfo = GetRequestWorkflowId(requestId);
        var httpWebRequest = Handler.BuildRequest(this.MSMBaseUrl + string.Format("/api/serviceDesk/operational/workflows/{0}", workflowInfo.WorkflowId), null, "GET");

        JObject requestWorkflowResponse = JObject.Parse(Handler.ProcessRequest(httpWebRequest, "Bearer " + this.MarvalAPIKey));
        Log.Information("Workflows from Marval raw is " + requestWorkflowResponse);
        WorkflowReadResponse response = requestWorkflowResponse["entity"].ToObject<WorkflowReadResponse>();
        string statesAsString = JsonConvert.SerializeObject(response.data.states, Newtonsoft.Json.Formatting.Indented);

        var distinctObjects = response.data.states
   .GroupBy(obj => obj.Id)
   .Select(group => group.First())
   .ToList();

        foreach (var obj in distinctObjects)
        {

            if (obj.NextWorkflowStatusIds == null)
            {
                obj.NextWorkflowStatusIds = new List<int>();
            }

            obj.NextWorkflowStatusIds = obj.NextWorkflowStatusIds
                .Where(id => distinctObjects.Any(o => o.Id == id))
                .ToList();
        }

        Log.Information("Target states distinct is " + JsonConvert.SerializeObject(distinctObjects, Newtonsoft.Json.Formatting.Indented));
        var result = GetPathToState(distinctObjects, workflowInfo.StatusId, targetStateName, 0);
        List<int> path = result.Item1;
        int targetStateID = result.Item2;
        int endStateid = 0;
        if (path.Count > 0)
        {
            Log.Information("Path to " + targetStateName);
            foreach (int id in path)
            {
                
                Dictionary<string, object> workflowUpdate = new Dictionary<string, object>();
                workflowUpdate["WorkflowStatusId"] = id;
                var httpWebRequest4 = Handler.BuildRequest(this.MSMBaseUrl + string.Format("/api/serviceDesk/integration/requests/{0}/partial", requestId), JsonHelper.ToJson(workflowUpdate), "PUT");
                var moveStatusResponse = Handler.ProcessRequest(httpWebRequest4, "Bearer " + this.MarvalAPIKey);
                endStateid = id;
            }

            var workflowInfoEndState = GetRequestWorkflowId(requestId);

            if (targetStateID == workflowInfoEndState.StatusId)
            {
                Log.Information("Target state is " + targetStateID);
                // AddMsmNote(requestId, "The status has been moved to \"" + targetStateName + "\"");
            }
            else
            {
                // AddMsmNote(requestId, "The Entra integration tried to move the status to " + targetStateName + " but was unable to due to a business rule violation");
            }
        }
        else
        {
            Log.Information("Target state not found in the workflow  " + targetStateName);
        }





    }

    static Tuple<List<int>, int> GetPathToState(List<State> states, int startStateID, string targetStateName, int targetstaticstate, List<List<int>> currBranches = null, int recurrNum = 0)
    {
        State targetState = states.Find(state => state.Name == targetStateName);
        Log.Information("Using New GetPathToState");

        int endStateID = targetState.Id;

        if (targetstaticstate == 0)
        {
            Log.Information("Setting target state to " + endStateID + " in GetPathToState");
            targetstaticstate = endStateID;
        }

        if (endStateID == startStateID)
        {
            //Log.Information("State already at end state");
            return Tuple.Create(new List<int>(), targetstaticstate);
        }
        if (!states.Exists(state2 => state2.Id == startStateID) || !states.Exists(endState => endState.Id == endStateID))
        {
            return Tuple.Create(new List<int>(), -1);
            //Log.Information("startStateID or end state could not be found");        // EXCEPTION
            // Handle workflow not containing start or end state
        }

        // Create initial branch
        if (currBranches == null || currBranches.Count == 0)
        {
            List<int> startList = new List<int>();
            startList.Add(startStateID);
            currBranches = new List<List<int>>();
            currBranches.Add(startList);
        }

        List<List<int>> newBranches = new List<List<int>>();
        // string jsonstates = JsonConvert.SerializeObject(currBranches, Formatting.Indented);

        List<int> prevLastIds = new List<int>();

        foreach (List<int> branch in currBranches)
        {
            int lastID = branch[branch.Count - 1]; // The last ID in this branch.
            if (prevLastIds.Contains(lastID)) // Prevent duplicates by skipping over this branch if a previous branch already exists for this ID.
            {
                continue;
            }
            // Add a new branch to newBranches with the next ID or return if one of the new branches has the end state.
            foreach (int nextID in states.Find(state => state.Id == lastID).NextWorkflowStatusIds)
            {
                List<int> newBranch = new List<int>(branch);
                newBranch.Add(nextID);

                if (nextID == endStateID)
                { return Tuple.Create(newBranch, targetstaticstate); }
                else { newBranches.Add(newBranch); }
            }
            prevLastIds.Add(lastID);
        }

        recurrNum++;
        if (recurrNum > states.Count)
        {
            Log.Information("Recursion limit (number of states) reached, returning empty path");
            return Tuple.Create(new List<int>(), 0);
        }
        return GetPathToState(states, startStateID, targetStateName, targetstaticstate, newBranches, recurrNum);
    }


    private WorkflowInfo GetRequestWorkflowId(int requestId)
    {
        Log.Information("Getting request workflow from requestId " + requestId);
        var httpWebRequest2 = Handler.BuildRequest(this.MSMBaseUrl + string.Format("/api/serviceDesk/operational/requests/{0}", requestId), null, "GET");
        var requestIdResponse = JObject.Parse(Handler.ProcessRequest(httpWebRequest2, "Bearer " + this.MarvalAPIKey));
        var workflowIdToken = requestIdResponse["entity"]["data"]["requestStatus"]["workflowStatus"]["workflow"]["id"];
        var statusIdToken = requestIdResponse["entity"]["data"]["requestStatus"]["workflowStatus"]["id"];

        int workflowId = workflowIdToken.Value<int>();
        int statusId = statusIdToken.Value<int>();

        return new WorkflowInfo { WorkflowId = workflowId, StatusId = statusId };
    }

    private void AddMsmNote(int requestNumber, string note)
    {
        Log.Information("Adding note with ID " + requestNumber);
        IDictionary<string, object> body = new Dictionary<string, object>();
        body.Add("id", requestNumber);
        body.Add("content", note);
        body.Add("type", "public");
        string jsonNote = JsonHelper.ToJson(body);
        Log.Information("Have json note as " + jsonNote);
        var httpWebRequest = Handler.BuildRequest(this.MSMBaseUrl + string.Format("/api/serviceDesk/operational/requests/{0}/notes/", requestNumber), JsonHelper.ToJson(body), "POST");
        Handler.ProcessRequest(httpWebRequest, "Bearer " + this.MarvalAPIKey);
    }
    private static HttpWebRequest BuildRequest(string uri = null, string body = null, string method = "GET")
    {
        var request = WebRequest.Create(new UriBuilder(uri).Uri) as HttpWebRequest;
        // Log.Information("Request URI is " + uri);
        // Log.Information("Request body is " + body);
        //  Log.Information("Building request " + request);
        request.Method = method.ToUpperInvariant();
        request.ContentType = "application/json";
        if (body == null) return request;
        using (var writer = new StreamWriter(request.GetRequestStream()))
        {
            // Log.Information("body is " + body);
            writer.Write(body);
        }

        return request;
    }
    private static string ProcessRequest(HttpWebRequest request, string credentials)
    {
        //  Log.Information("Processing request with credentials " + credentials);
        var result = "";
        try
        {
            request.Headers.Add("Authorization", credentials);
            HttpWebResponse response = request.GetResponse() as HttpWebResponse;
            using (StreamReader reader = new StreamReader(response.GetResponseStream()))
            {
                result = reader.ReadToEnd();
            }
        }
        catch (WebException webEx)
        {

            var errResp = webEx.Response;
            Log.Information("Have error response, response is " + errResp);
            using (var stream = errResp.GetResponseStream())
            {
                using (var reader = new StreamReader(stream))
                {
                    result = reader.ReadToEnd();
                    Log.Information("Result from stream error " + result);
                }
            }

        }
        return result;
    }
    internal class JsonHelper
    {
        public static string ToJson(object obj)
        {
            return JsonConvert.SerializeObject(obj);
        }

        public static dynamic FromJson(string json)
        {
            return JObject.Parse(json);
        }
    }

}
