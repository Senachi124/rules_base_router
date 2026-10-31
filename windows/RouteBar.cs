// Native Windows client. Builds with the .NET Framework compiler shipped with Windows.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows.Forms;

[assembly: System.Reflection.AssemblyVersion("0.2.2.0")]
[assembly: System.Reflection.AssemblyFileVersion("0.2.2.0")]

namespace RouteBar.Windows
{
    public sealed class Vpn { public string wireguard_config { get; set; } }
    public sealed class Dns
    {
        public string server { get; set; }
        public string via { get; set; }
        public string strategy { get; set; }
        public Dns() { server = "1.1.1.1"; via = "direct"; strategy = "auto"; }
    }
    public sealed class Selectors
    {
        public string[] apps { get; set; }
        public string[] process_names { get; set; }
        public string[] domains { get; set; }
        public string[] domain_suffixes { get; set; }
        public string[] ip_cidrs { get; set; }
        public Selectors() { apps = process_names = domains = domain_suffixes = ip_cidrs = new string[0]; }
        public override string ToString()
        {
            var programs = apps.Concat(process_names).ToArray();
            var destinations = domains.Concat(domain_suffixes.Select(s => s + " + subdomains")).Concat(ip_cidrs).ToArray();
            return (programs.Length == 0 ? "Any app" : "App/process: " + string.Join(" OR ", programs)) +
                " AND " + (destinations.Length == 0 ? "any destination" : "Destination: " + string.Join(" OR ", destinations));
        }
    }
    public sealed class Rule
    {
        public string name { get; set; }
        public Selectors match { get; set; }
        public string via { get; set; }
        public Rule() { name = "New rule"; match = new Selectors(); via = "direct"; }
    }
    public sealed class Routing
    {
        public string @default { get; set; }
        public List<Rule> rules { get; set; }
        public Routing() { @default = "direct"; rules = new List<Rule>(); }
    }
    public sealed class Document
    {
        public int version { get; set; }
        public Dictionary<string, Vpn> vpns { get; set; }
        public Dns dns { get; set; }
        public Routing routing { get; set; }
        public Document() { version = 1; vpns = new Dictionary<string, Vpn>(); dns = new Dns(); routing = new Routing(); }
    }
    internal static class DefaultPreset
    {
        internal static Document Create(string root)
        {
            var doc = new Document();
            doc.vpns.Add("vm1", new Vpn { wireguard_config = Path.Combine(root, "vm1.conf") });
            doc.dns = new Dns { server = "1.1.1.1", via = "vm1", strategy = "prefer_ipv4" };
            doc.routing.rules.Add(new Rule { name = "codex", via = "vm1", match = new Selectors {
                process_names = new[] { "ChatGPT.exe", "codex.exe", "codex-code-mode-host.exe" } } });
            return doc;
        }
        internal static bool NeedsProfile(Document doc, string root)
        {
            Vpn vpn;
            return doc.vpns.TryGetValue("vm1", out vpn) &&
                string.Equals(vpn.wireguard_config, Path.Combine(root, "vm1.conf"), StringComparison.OrdinalIgnoreCase) &&
                !File.Exists(vpn.wireguard_config);
        }
    }
    internal static class Store
    {
        internal static readonly string Root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "RouteBarWindows");
        internal static readonly string ConfigPath = Path.Combine(Root, "config.json");
        internal static JavaScriptSerializer Json() { return new JavaScriptSerializer { MaxJsonLength = 1024 * 1024, RecursionLimit = 100 }; }
        internal static DirectorySecurity Security()
        {
            var acl = new DirectorySecurity();
            acl.SetAccessRuleProtection(true, false);
            foreach (var sid in new[] { WindowsIdentity.GetCurrent().User, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null) })
                acl.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            return acl;
        }
        internal static void PrivateDirectory(string path)
        {
            if (Directory.Exists(path) && (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
                throw new IOException("RouteBar storage must not be a symbolic link or junction.");
            Directory.CreateDirectory(path, Security());
            Directory.SetAccessControl(path, Security());
        }
        internal static void Write(string path, string value)
        {
            string temp = Path.Combine(Path.GetDirectoryName(path), Guid.NewGuid().ToString("N") + ".tmp");
            try
            {
                using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    var bytes = new UTF8Encoding(false).GetBytes(value);
                    stream.Write(bytes, 0, bytes.Length); stream.Flush(true);
                }
                if (File.Exists(path)) File.Replace(temp, path, null); else File.Move(temp, path);
            }
            finally { if (File.Exists(temp)) File.Delete(temp); }
        }
        internal static void Save(Document doc) { PrivateDirectory(Root); Write(ConfigPath, Json().Serialize(doc)); }
        internal static Document Clone(Document doc) { return Json().Deserialize<Document>(Json().Serialize(doc)); }
    }
    internal static class Backend
    {
        internal static readonly string Controller = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "routebar-v2.exe");
        internal static string Quote(string value)
        {
            // CommandLineToArgvW quoting, including paths ending with backslashes.
            var b = new StringBuilder("\""); int slashes = 0;
            foreach (char c in value)
            {
                if (c == '\\') { slashes++; continue; }
                b.Append('\\', c == '"' ? slashes * 2 + 1 : slashes); slashes = 0; b.Append(c);
            }
            return b.Append('\\', slashes * 2).Append('"').ToString();
        }
        internal static ProcessStartInfo StartInfo(params string[] args)
        {
            return new ProcessStartInfo(Controller, string.Join(" ", args.Select(Quote))) {
                UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true,
                RedirectStandardError = true, RedirectStandardInput = true,
                StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8,
                WorkingDirectory = AppDomain.CurrentDomain.BaseDirectory
            };
        }
        internal static string Call(params string[] args)
        {
            using (var process = new Process { StartInfo = StartInfo(args) })
            {
                var output = new StringBuilder(); var error = new StringBuilder();
                process.OutputDataReceived += (s, e) => { if (e.Data != null) lock (output) { if (output.Length < 1024 * 1024) output.AppendLine(e.Data); } };
                process.ErrorDataReceived += (s, e) => { if (e.Data != null) lock (error) { if (error.Length < 16384) error.AppendLine(e.Data); } };
                process.Start(); process.StandardInput.Close(); process.BeginOutputReadLine(); process.BeginErrorReadLine();
                if (!process.WaitForExit(30000)) { process.Kill(); process.WaitForExit(); throw new IOException("Controller timed out."); }
                process.WaitForExit();
                if (process.ExitCode != 0) throw new IOException(ErrorMessage(error.ToString()));
                if (output.Length >= 1024 * 1024) throw new IOException("Controller output exceeds 1 MiB.");
                return output.ToString();
            }
        }
        internal static Document Load(string file) { return Store.Json().Deserialize<Document>(Call("config-inspect", "-c", file)); }
        internal static string ErrorMessage(string text)
        {
            try { var data = Store.Json().Deserialize<Dictionary<string, object>>(text.Trim()); object error; if (data.TryGetValue("error", out error)) return Convert.ToString(error); } catch { }
            return string.IsNullOrWhiteSpace(text) ? "The controller failed without an error message." : text.Trim();
        }
        internal static bool IsAdmin { get { return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator); } }
    }
    // Explicit services make offline regression tests independent of user storage.
    internal sealed class AppServices
    {
        internal readonly string Root;
        internal readonly Func<string[], string> Call;
        internal string ConfigPath { get { return Path.Combine(Root, "config.json"); } }
        internal AppServices(string root, Func<string[], string> call) { Root = Path.GetFullPath(root); Call = call; }
        internal static AppServices Production() { return new AppServices(Store.Root, args => Backend.Call(args)); }
        internal Document Load(string path) { return Store.Json().Deserialize<Document>(Call(new[] { "config-inspect", "-c", path })); }
        internal Document LoadOrDefault() { return File.Exists(ConfigPath) ? Load(ConfigPath) : DefaultPreset.Create(Root); }
        internal Document Normalize(Document candidate)
        {
            Store.PrivateDirectory(Root);
            string path = Path.Combine(Root, "draft-" + Guid.NewGuid().ToString("N") + ".json");
            try { Store.Write(path, Store.Json().Serialize(candidate)); return Load(path); }
            catch (Exception ex) { throw new IOException(Backend.ErrorMessage(ex.Message), ex); }
            finally { if (File.Exists(path)) File.Delete(path); }
        }
        internal void Save(Document doc) { Store.PrivateDirectory(Root); Store.Write(ConfigPath, Store.Json().Serialize(doc)); }
        internal static string[] SnapshotWarnings(string result)
        {
            var data = Store.Json().Deserialize<Dictionary<string, object>>(result);
            object valid; if (!data.TryGetValue("valid", out valid) || !Convert.ToBoolean(valid)) throw new IOException("Configuration validation did not succeed.");
            object warnings; if (!data.TryGetValue("warnings", out warnings) || warnings == null) return new string[0];
            return ((System.Collections.IEnumerable)warnings).Cast<object>().Select(Convert.ToString).ToArray();
        }
    }
    internal interface IConnection
    {
        bool IsRunning { get; }
        void Start(Action<string> log);
        void Stop();
        void Cleanup();
    }
    internal sealed class TransitionException : IOException
    {
        internal readonly IConnection Active;
        internal readonly bool Restored;
        internal readonly bool FailedBeforeChange;
        internal TransitionException(string message, Exception inner, IConnection active, bool restored, bool before)
            : base(message, inner) { Active = active; Restored = restored; FailedBeforeChange = before; }
    }
    internal static class ConnectionTransaction
    {
        internal static void Cleanup(IConnection connection, Action<string> log)
        {
            if (connection == null) return;
            try { connection.Cleanup(); } catch (Exception ex) { log("Temporary configuration cleanup failed: " + ex.Message); }
        }
        internal static IConnection Replace(IConnection previous, IConnection candidate, Action<string> log)
        {
            if (previous != null)
            {
                try { previous.Stop(); }
                catch (Exception ex) { Cleanup(candidate, log); throw new TransitionException("Could not stop the existing connection. Its controls remain available. " + ex.Message, ex, previous, false, true); }
            }
            try { candidate.Start(log); }
            catch (Exception startError)
            {
                try { candidate.Stop(); }
                catch (Exception stopError)
                {
                    log("Failed replacement also failed to stop: " + stopError.Message);
                    if (candidate.IsRunning) throw new TransitionException("Replacement failed and could not be stopped. Disconnect it before retrying.", startError, candidate, false, false);
                }
                Cleanup(candidate, log); // Cleanup must never prevent restoration.
                if (previous != null)
                {
                    try { previous.Start(log); }
                    catch (Exception restoreError)
                    {
                        log("Rollback failed: " + restoreError.Message);
                        if (!previous.IsRunning) Cleanup(previous, log);
                        throw new TransitionException(startError.Message + " Previous connection could not be restored: " + restoreError.Message,
                            startError, previous.IsRunning ? previous : null, false, false);
                    }
                    throw new TransitionException(startError.Message + " Previous connection restored.", startError, previous, true, false);
                }
                throw new TransitionException(startError.Message, startError, null, false, false);
            }
            Cleanup(previous, log);
            return candidate;
        }
    }
    // Profiles are copied with the document so rollback does not reread edited files.
    internal sealed class Connection : IConnection, IDisposable
    {
        internal readonly string DirectoryPath;
        internal readonly string ConfigPath;
        internal readonly string[] Warnings;
        private Process process;
        public bool IsRunning { get { return process != null && !process.HasExited; } }
        internal Connection(Document document) : this(document, AppServices.Production()) { }
        internal Connection(Document document, AppServices services)
        {
            Store.PrivateDirectory(services.Root);
            DirectoryPath = Path.Combine(services.Root, "session-" + Guid.NewGuid().ToString("N"));
            ConfigPath = Path.Combine(DirectoryPath, "config.json");
            Store.PrivateDirectory(DirectoryPath);
            try
            {
                var copy = Store.Clone(document); int index = 0;
                foreach (var vpn in copy.vpns.Values)
                {
                    string target = Path.Combine(DirectoryPath, "profile-" + index++ + ".conf");
                    var info = new FileInfo(vpn.wireguard_config);
                    if (info.Length > 128 * 1024) throw new IOException("WireGuard profile exceeds 128 KiB.");
                    Store.Write(target, File.ReadAllText(vpn.wireguard_config)); vpn.wireguard_config = target;
                }
                Store.Write(ConfigPath, Store.Json().Serialize(copy));
                Warnings = AppServices.SnapshotWarnings(services.Call(new[] { "validate", "-c", ConfigPath }));
            }
            catch (Exception ex)
            {
                try { Directory.Delete(DirectoryPath, true); } catch (Exception cleanup) { throw new IOException(Backend.ErrorMessage(ex.Message) + " Temporary configuration cleanup also failed: " + cleanup.Message, ex); }
                throw new IOException(Backend.ErrorMessage(ex.Message), ex);
            }
        }
        public void Start(Action<string> log)
        {
            if (IsRunning) throw new InvalidOperationException("Connection is already running.");
            if (process != null) { process.Dispose(); process = null; }
            var ready = new TaskCompletionSource<bool>();
            var child = new Process { StartInfo = Backend.StartInfo("run", "-c", ConfigPath), EnableRaisingEvents = true };
            child.StartInfo.CreateNoWindow = false; child.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
            child.OutputDataReceived += (s, e) => {
                if (e.Data == null) return;
                try
                {
                    var data = Store.Json().Deserialize<Dictionary<string, object>>(e.Data);
                    object kind; if (data.TryGetValue("event", out kind) && (string)kind == "running") ready.TrySetResult(true);
                    object message; if (data.TryGetValue("message", out message)) log(Convert.ToString(message));
                }
                catch { log("Controller emitted an unreadable status message."); }
            };
            child.ErrorDataReceived += (s, e) => { if (e.Data != null) log(Backend.ErrorMessage(e.Data)); };
            child.Exited += (s, e) => ready.TrySetResult(false);
            bool started = false;
            try
            {
                child.Start(); started = true; process = child;
                child.BeginOutputReadLine(); child.BeginErrorReadLine();
                if (!ready.Task.Wait(30000) || !ready.Task.Result || !IsRunning) throw new IOException("VPN engine did not start. See Logs for details.");
            }
            catch (Exception startError)
            {
                if (!started) child.Dispose();
                else { try { Stop(); } catch (Exception stopError) { log("Startup cleanup failed: " + stopError.Message); } }
                throw new IOException(startError.Message, startError);
            }
        }
        public void Stop()
        {
            var child = process; if (child == null) return;
            if (!child.HasExited)
            {
                try { child.StandardInput.WriteLine("stop"); child.StandardInput.Flush(); child.StandardInput.Close(); }
                catch (IOException) { } catch (InvalidOperationException) { }
                if (!child.WaitForExit(8000))
                {
                    child.Kill();
                    if (!child.WaitForExit(5000)) throw new IOException("Controller did not stop; keep RouteBar open and retry Disconnect.");
                }
            }
            // Only release ownership once exit is confirmed; never lose the stop control.
            child.Dispose(); process = null;
        }
        public void Cleanup()
        {
            if (IsRunning) throw new InvalidOperationException("Cannot remove a running connection's configuration.");
            if (Directory.Exists(DirectoryPath)) Directory.Delete(DirectoryPath, true);
        }
        public void Dispose() { Stop(); Cleanup(); }
    }
    internal sealed class RuleDialog : Form
    {
        private readonly TextBox name = new TextBox(), apps = new TextBox(), processes = new TextBox(), domains = new TextBox(), suffixes = new TextBox(), cidrs = new TextBox();
        private readonly ComboBox via = new ComboBox();
        private readonly Label error = new Label();
        private readonly Func<Rule, Task<Rule>> validate;
        private readonly Button save;
        private bool saving;
        internal Rule Result;
        internal string ValidationMessage { get { return error.Text; } }
        internal RuleDialog(Rule rule, IEnumerable<string> exits) : this(rule, exits, r => Task.FromResult(r)) { }
        internal RuleDialog(Rule rule, IEnumerable<string> exits, Func<Rule, Task<Rule>> validator)
        {
            validate = validator;
            Text = "Routing rule"; Font = new Font("Segoe UI", 10); AutoScaleDimensions = new SizeF(7F, 19F); AutoScaleMode = AutoScaleMode.Font;
            Size = new Size(700, 600); MinimumSize = new Size(520, 420); StartPosition = FormStartPosition.CenterParent; BackColor = SystemColors.Window;
            var scroll = new Panel { Dock = DockStyle.Fill, AutoScroll = true, Padding = new Padding(16) }; Controls.Add(scroll);
            var layout = new TableLayoutPanel { Dock = DockStyle.Top, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, ColumnCount = 2, RowCount = 9 };
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 31)); layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 69)); scroll.Controls.Add(layout);
            Add(layout, "Rule name", name, 0); Add(layout, "Applications (.exe)", apps, 1); Add(layout, "Process names", processes, 2);
            Add(layout, "Exact domains", domains, 3); Add(layout, "Domain suffixes", suffixes, 4); Add(layout, "IP ranges (CIDR)", cidrs, 5); Add(layout, "Route through", via, 6);
            name.Text = rule.name; apps.Text = string.Join("; ", rule.match.apps); processes.Text = string.Join("; ", rule.match.process_names);
            domains.Text = string.Join("; ", rule.match.domains); suffixes.Text = string.Join("; ", rule.match.domain_suffixes); cidrs.Text = string.Join("; ", rule.match.ip_cidrs);
            via.DropDownStyle = ComboBoxStyle.DropDownList; via.Items.AddRange(exits.Cast<object>().ToArray()); via.SelectedItem = rule.via;
            if (via.SelectedIndex < 0 && via.Items.Count > 0) via.SelectedIndex = 0;
            var hint = new Label { Text = "Separate values with semicolons. App/process alternatives are OR; destination alternatives are OR. If both groups are set, both must match. A suffix includes the domain itself and its subdomains.", AutoSize = true, Dock = DockStyle.Fill, Margin = new Padding(3, 10, 3, 10) };
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize)); layout.Controls.Add(hint, 0, 7); layout.SetColumnSpan(hint, 2);
            error.AutoSize = true; error.Dock = DockStyle.Fill; error.ForeColor = Color.DarkRed; error.AccessibleName = "Rule validation error";
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize)); layout.Controls.Add(error, 0, 8); layout.SetColumnSpan(error, 2);
            var buttons = new FlowLayoutPanel { Dock = DockStyle.Bottom, AutoSize = true, WrapContents = true, Padding = new Padding(16, 8, 16, 12) };
            var browse = new Button { Text = "Browse app...", AutoSize = true };
            browse.Click += (s, e) => { using (var dialog = new OpenFileDialog { Filter = "Applications|*.exe", CheckFileExists = true }) if (dialog.ShowDialog(this) == DialogResult.OK) apps.Text = apps.Text.Trim().Length == 0 ? dialog.FileName : apps.Text + "; " + dialog.FileName; };
            save = new Button { Text = "Save rule", AutoSize = true }; var cancel = new Button { Text = "Cancel", AutoSize = true, DialogResult = DialogResult.Cancel };
            save.Click += async (s, e) => await TrySave();
            buttons.Controls.AddRange(new Control[] { browse, save, cancel }); Controls.Add(buttons); AcceptButton = save; CancelButton = cancel;
            FormClosing += (s, e) => { if (saving) e.Cancel = true; };
        }
        internal async Task<bool> TrySave()
        {
            if (saving) return false;
            saving = true; save.Enabled = false; error.Text = "Validating rule...";
            try
            {
                var draft = new Rule { name = name.Text.Trim(), via = Convert.ToString(via.SelectedItem), match = new Selectors {
                    apps = Split(apps.Text), process_names = Split(processes.Text), domains = Split(domains.Text), domain_suffixes = Split(suffixes.Text), ip_cidrs = Split(cidrs.Text) } };
                Result = await validate(draft); error.Text = ""; saving = false; DialogResult = DialogResult.OK; Close(); return true;
            }
            catch (Exception ex)
            {
                error.Text = Backend.ErrorMessage(ex.Message);
                string detail = error.Text.ToLowerInvariant();
                Control invalid = detail.Contains("cidr") ? cidrs : detail.Contains("process name") ? processes :
                    detail.Contains("app path") ? apps : detail.Contains("domain") ? (domains.Text.Length > 0 ? domains : suffixes) :
                    detail.Contains("vpn") || detail.Contains("via") ? (Control)via : name;
                invalid.Focus(); var box = invalid as TextBox; if (box != null) box.SelectAll(); return false;
            }
            finally { saving = false; if (!IsDisposed) save.Enabled = true; }
        }
        private static void Add(TableLayoutPanel layout, string label, Control control, int row)
        {
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.Controls.Add(new Label { Text = label, AutoSize = true, Dock = DockStyle.Fill, Margin = new Padding(3, 8, 8, 8) }, 0, row);
            control.AccessibleName = label; control.Dock = DockStyle.Top; control.Margin = new Padding(3, 6, 3, 8); layout.Controls.Add(control, 1, row);
        }
        private static string[] Split(string text) { return text.Split(';').Select(s => s.Trim()).Where(s => s.Length > 0).ToArray(); }
    }
    internal sealed class MainForm : Form
    {
        private Document document = new Document();
        private IConnection active;
        private string savedDocument = "", appliedDocument = "";
        private readonly AppServices services;
        private readonly bool initialize;
        private readonly bool connectOnLoad;
        private readonly InstanceLease lease;
        private bool busy, quitting, handoff, refreshing;
        private readonly Label status = new Label(), stateSummary = new Label(), warningSummary = new Label(), emptyRules = new Label(), emptyVpns = new Label();
        private readonly ListView rules = new ListView(), vpns = new ListView();
        private readonly TextBox logs = new TextBox(), dnsServer = new TextBox();
        private readonly ComboBox dnsVia = new ComboBox(), strategy = new ComboBox(), fallback = new ComboBox();
        private readonly FlowLayoutPanel toolbar = new FlowLayoutPanel();
        private readonly TabControl tabs = new TabControl();
        private readonly NotifyIcon tray = new NotifyIcon();
        private readonly System.Windows.Forms.Timer timer = new System.Windows.Forms.Timer { Interval = 500 };
        private Button connect, disconnect, editRule, removeRule, moveUp, moveDown, removeExit;
        internal MainForm() : this(AppServices.Production(), true, false, null) { }
        internal MainForm(AppServices appServices, bool initializeServices) : this(appServices, initializeServices, false, null) { }
        internal MainForm(AppServices appServices, bool initializeServices, bool autoConnect, InstanceLease instance)
        {
            services = appServices; initialize = initializeServices; connectOnLoad = autoConnect; lease = instance;
            Text = "RouteBar for Windows 0.2.2"; Font = new Font("Segoe UI", 10); AutoScaleDimensions = new SizeF(7F, 19F); AutoScaleMode = AutoScaleMode.Font;
            ClientSize = new Size(1080, 760); MinimumSize = new Size(760, 560); StartPosition = FormStartPosition.CenterScreen; BackColor = SystemColors.Control;
            var layout = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(20), RowCount = 7, ColumnCount = 1 };
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            for (int i = 0; i < 5; i++) layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100)); layout.RowStyles.Add(new RowStyle(SizeType.AutoSize)); Controls.Add(layout);
            layout.Controls.Add(new Label { Text = "RouteBar  /  Windows", Font = new Font("Segoe UI", 25, FontStyle.Bold), ForeColor = Color.FromArgb(24, 43, 76), AutoSize = true, Dock = DockStyle.Fill, Margin = new Padding(3, 3, 3, 12) }, 0, 0);
            status.Text = "Disconnected"; status.AutoSize = true; status.Dock = DockStyle.Fill; status.AccessibleName = "Connection status"; layout.Controls.Add(status, 0, 1);
            stateSummary.AutoSize = true; stateSummary.Dock = DockStyle.Fill; stateSummary.AccessibleName = "Configuration state"; stateSummary.Margin = new Padding(3, 3, 3, 8); layout.Controls.Add(stateSummary, 0, 2);
            warningSummary.AutoSize = true; warningSummary.Dock = DockStyle.Fill; warningSummary.ForeColor = Color.DarkGoldenrod; warningSummary.AccessibleName = "Configuration warnings"; layout.Controls.Add(warningSummary, 0, 3);
            toolbar.Dock = DockStyle.Fill; toolbar.AutoSize = true; toolbar.WrapContents = true; toolbar.AccessibleName = "Connection and configuration actions"; layout.Controls.Add(toolbar, 0, 4);
            connect = Button(toolbar, "Connect", async () => await Connect());
            disconnect = Button(toolbar, "Disconnect", async () => await Disconnect());
            Button(toolbar, "Validate visible settings", async () => await ValidateConfiguration());
            Button(toolbar, "Save settings", async () => await SaveCandidate(CaptureDraft(), null));
            Button(toolbar, "Import config...", async () => await ImportConfig()); Button(toolbar, "Export config...", Export);
            tabs.Dock = DockStyle.Fill; tabs.AccessibleName = "RouteBar settings pages"; layout.Controls.Add(tabs, 0, 5);
            var rulesPage = Page("Routing rules"); var rulesLayout = Panel(rulesPage);
            var ruleButtons = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, WrapContents = true, AccessibleName = "Rule actions" };
            Button(ruleButtons, "Add rule", async () => await EditRule(false)); editRule = Button(ruleButtons, "Edit", async () => await EditRule(true));
            removeRule = Button(ruleButtons, "Remove", async () => await ChangeRules("remove")); moveUp = Button(ruleButtons, "Move up", async () => await ChangeRules("up")); moveDown = Button(ruleButtons, "Move down", async () => await ChangeRules("down"));
            SetupList(rules, "Ordered routing rules", new[] { "Priority", "Name", "Exit", "Match (AND between groups)" }, new[] { 60, 170, 110, 500 });
            SetupEmpty(emptyRules, "No routing rules yet. Import a VPN exit, then add an application or destination rule. Unmatched traffic uses the default route.");
            rulesLayout.Controls.Add(rules); rulesLayout.Controls.Add(emptyRules); rulesLayout.Controls.Add(ruleButtons);
            var vpnPage = Page("VPN exits"); var vpnLayout = Panel(vpnPage);
            var vpnButtons = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, WrapContents = true, AccessibleName = "VPN exit actions" };
            Button(vpnButtons, "Import WireGuard .conf...", async () => await ImportVpn()); removeExit = Button(vpnButtons, "Remove exit", async () => await RemoveVpn());
            SetupList(vpns, "Configured VPN exits", new[] { "Exit name", "Profile location" }, new[] { 180, 650 });
            SetupEmpty(emptyVpns, "No VPN exits. Import an exported WireGuard .conf to create an exit, then choose it in a rule or as the default route.");
            vpnLayout.Controls.Add(vpns); vpnLayout.Controls.Add(emptyVpns); vpnLayout.Controls.Add(vpnButtons);
            var dnsPage = Page("DNS and default route"); dnsPage.AutoScroll = true;
            var dnsLayout = new TableLayoutPanel { Dock = DockStyle.Top, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, Padding = new Padding(16), ColumnCount = 2, RowCount = 6 };
            dnsLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 32)); dnsLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 68)); dnsPage.Controls.Add(dnsLayout);
            var labels = new[] { "DNS server (IP address)", "DNS exit", "Address family", "Unmatched traffic" };
            var fields = new Control[] { dnsServer, dnsVia, strategy, fallback };
            for (int i = 0; i < fields.Length; i++)
            {
                dnsLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize)); dnsLayout.Controls.Add(new Label { Text = labels[i], AutoSize = true, Dock = DockStyle.Fill, Margin = new Padding(3, 8, 8, 8) }, 0, i);
                fields[i].AccessibleName = labels[i]; fields[i].Dock = DockStyle.Top; fields[i].Margin = new Padding(3, 6, 3, 8); dnsLayout.Controls.Add(fields[i], 1, i);
            }
            foreach (var combo in new[] { dnsVia, strategy, fallback }) combo.DropDownStyle = ComboBoxStyle.DropDownList;
            strategy.Items.AddRange(new object[] { "auto", "prefer_ipv4", "prefer_ipv6", "ipv4_only", "ipv6_only" });
            var dnsButtons = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true }; Button(dnsButtons, "Save DNS and default", async () => await SaveDns()); dnsLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize)); dnsLayout.Controls.Add(dnsButtons, 1, 4);
            var dnsHint = new Label { Text = "DNS uses a separate global policy. Selecting an app's VPN does not automatically route DNS through it. Validate, Connect and Export include the values currently shown here.", Dock = DockStyle.Fill, AutoSize = true, Margin = new Padding(3, 12, 3, 8) };
            dnsLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize)); dnsLayout.Controls.Add(dnsHint, 0, 5); dnsLayout.SetColumnSpan(dnsHint, 2);
            var logPage = Page("Logs"); logs.Multiline = true; logs.ReadOnly = true; logs.ScrollBars = ScrollBars.Both; logs.WordWrap = false; logs.Font = new Font("Consolas", 9); logs.Dock = DockStyle.Fill; logs.AccessibleName = "Connection and validation log"; logPage.Controls.Add(logs);
            layout.Controls.Add(new Label { Text = "First match wins. Apply restarts connections. No kill switch. Closing stops the VPN; minimizing keeps it running in the notification area.", AutoSize = true, Dock = DockStyle.Fill, Margin = new Padding(3, 12, 3, 3) }, 0, 6);
            rules.SelectedIndexChanged += (s, e) => UpdateActions(); vpns.SelectedIndexChanged += (s, e) => UpdateActions();
            dnsServer.TextChanged += (s, e) => DraftChanged(); foreach (var combo in new[] { dnsVia, strategy, fallback }) combo.SelectedIndexChanged += (s, e) => DraftChanged();
            rules.SizeChanged += (s, e) => ResizeColumns(rules); vpns.SizeChanged += (s, e) => ResizeColumns(vpns);
            FormClosing += OnClosing;
            if (initialize)
            {
                tray.Icon = SystemIcons.Application; tray.Visible = true; var menu = new ContextMenuStrip();
                menu.Items.Add("Show RouteBar", null, (s, e) => ShowWindow()); menu.Items.Add("Disconnect", null, async (s, e) => await Disconnect()); menu.Items.Add("Exit and disconnect", null, (s, e) => Close());
                tray.ContextMenuStrip = menu; tray.DoubleClick += (s, e) => ShowWindow(); Resize += (s, e) => { if (WindowState == FormWindowState.Minimized) Hide(); };
                Shown += async (s, e) => {
                    bool loaded = await Work(() => { Store.PrivateDirectory(services.Root); document = services.LoadOrDefault(); savedDocument = File.Exists(services.ConfigPath) ? Serialize(document) : ""; }, "Settings loaded", true);
                    if (loaded && DefaultPreset.NeedsProfile(document, services.Root)) status.Text = "Setup required: import a WireGuard profile in VPN exits to activate vm1. Codex routing is already prepared.";
                    if (loaded && connectOnLoad) await Connect();
                };
                timer.Tick += (s, e) => {
                    if (lease != null && lease.ActivationRequested) ShowWindow();
                    if (!busy && active != null && !active.IsRunning) { var ended = active; active = null; ConnectionTransaction.Cleanup(ended, Log); status.Text = "Disconnected: engine stopped unexpectedly. See Logs."; UpdateState(); }
                }; timer.Start();
            }
            savedDocument = Serialize(document); RefreshDocument(true);
        }
        private static string Serialize(Document doc) { return Store.Json().Serialize(doc); }
        private static Button Button(Control parent, string text, Action action)
        {
            var button = new Button { Text = text, AutoSize = true, Padding = new Padding(7, 4, 7, 4), FlatStyle = FlatStyle.System };
            button.Click += (s, e) => action(); parent.Controls.Add(button); return button;
        }
        private TabPage Page(string title) { var page = new TabPage(title) { BackColor = SystemColors.Window, Padding = new Padding(8) }; tabs.TabPages.Add(page); return page; }
        private static Panel Panel(Control parent) { var panel = new Panel { Dock = DockStyle.Fill }; parent.Controls.Add(panel); return panel; }
        private static void SetupEmpty(Label label, string text) { label.Text = text; label.Dock = DockStyle.Top; label.AutoSize = true; label.Padding = new Padding(8); }
        private static void SetupList(ListView list, string name, string[] labels, int[] widths)
        {
            list.AccessibleName = name; list.Dock = DockStyle.Fill; list.View = View.Details; list.FullRowSelect = true; list.HideSelection = false; list.MultiSelect = false;
            for (int i = 0; i < labels.Length; i++) list.Columns.Add(labels[i], widths[i]);
        }
        private static void ResizeColumns(ListView list)
        {
            if (list.Columns.Count == 0) return; int used = 0; for (int i = 0; i < list.Columns.Count - 1; i++) used += list.Columns[i].Width;
            list.Columns[list.Columns.Count - 1].Width = Math.Max(180, list.ClientSize.Width - used - SystemInformation.VerticalScrollBarWidth - 5);
        }
        private void ShowWindow() { Show(); WindowState = FormWindowState.Normal; Activate(); }
        private IEnumerable<string> Exits { get { return new[] { "direct" }.Concat(document.vpns.Keys); } }
        internal Document CaptureDraft()
        {
            var candidate = Store.Clone(document); candidate.dns.server = dnsServer.Text.Trim(); candidate.dns.via = Convert.ToString(dnsVia.SelectedItem);
            candidate.dns.strategy = Convert.ToString(strategy.SelectedItem); candidate.routing.@default = Convert.ToString(fallback.SelectedItem); return candidate;
        }
        internal void RefreshDocument(bool replaceDnsDraft = false)
        {
            string selectedRule = rules.SelectedItems.Count > 0 ? rules.SelectedItems[0].Name : null;
            string selectedExit = vpns.SelectedItems.Count > 0 ? vpns.SelectedItems[0].Name : null;
            var draft = replaceDnsDraft ? document : CaptureDraft(); refreshing = true;
            try
            {
                rules.BeginUpdate(); rules.Items.Clear(); for (int i = 0; i < document.routing.rules.Count; i++) { var r = document.routing.rules[i]; var item = new ListViewItem(new[] { (i + 1).ToString(), r.name, r.via, r.match.ToString() }) { Name = r.name }; rules.Items.Add(item); if (r.name == selectedRule) { item.Selected = true; item.Focused = true; item.EnsureVisible(); } } rules.EndUpdate();
                vpns.BeginUpdate(); vpns.Items.Clear(); foreach (var pair in document.vpns) { var item = new ListViewItem(new[] { pair.Key, pair.Value.wireguard_config }) { Name = pair.Key }; vpns.Items.Add(item); if (pair.Key == selectedExit) item.Selected = true; } vpns.EndUpdate();
                foreach (var combo in new[] { dnsVia, fallback }) { combo.Items.Clear(); combo.Items.AddRange(Exits.Cast<object>().ToArray()); }
                dnsServer.Text = draft.dns.server; SelectValue(dnsVia, draft.dns.via); SelectValue(strategy, draft.dns.strategy); SelectValue(fallback, draft.routing.@default);
                emptyRules.Visible = document.routing.rules.Count == 0; emptyVpns.Visible = document.vpns.Count == 0;
            }
            finally { refreshing = false; }
            UpdateState();
        }
        private static void SelectValue(ComboBox combo, string value) { if (!combo.Items.Contains(value)) combo.Items.Add(value); combo.SelectedItem = value; }
        private void DraftChanged() { if (!refreshing) UpdateState(); }
        private void UpdateState()
        {
            bool running = active != null && active.IsRunning; string draft = Serialize(CaptureDraft()); bool unsaved = draft != savedDocument; bool unapplied = running && draft != appliedDocument;
            stateSummary.Text = (unsaved ? "Unsaved settings" : "Settings saved") + (running ? (unapplied ? " • Changes not applied to the running connection" : " • Applied to running connection") : " • Default route when connected: " + CaptureDraft().routing.@default);
            connect.Text = running ? "Apply changes" : "Connect"; tray.Text = running ? "RouteBar: running (egress not verified)" : "RouteBar: disconnected";
            UpdateActions();
        }
        private void UpdateActions()
        {
            if (connect == null || disconnect == null || editRule == null) return;
            bool selected = rules.SelectedIndices.Count > 0; int index = selected ? rules.SelectedIndices[0] : -1;
            editRule.Enabled = removeRule.Enabled = !busy && selected; moveUp.Enabled = !busy && index > 0; moveDown.Enabled = !busy && index >= 0 && index < rules.Items.Count - 1;
            removeExit.Enabled = !busy && vpns.SelectedItems.Count > 0; disconnect.Enabled = !busy && active != null;
        }
        private void Log(string message)
        {
            if (IsDisposed || Disposing) return;
            if (InvokeRequired) { try { BeginInvoke(new Action<string>(Log), message); } catch (InvalidOperationException) { } return; }
            if (logs.TextLength > 64000) logs.Text = logs.Text.Substring(logs.TextLength - 32000);
            logs.AppendText(DateTime.Now.ToString("HH:mm:ss") + "  " + message + Environment.NewLine);
        }
        private void ShowWarnings(string[] warnings)
        {
            if (InvokeRequired) { BeginInvoke(new Action<string[]>(ShowWarnings), new object[] { warnings }); return; }
            warningSummary.Text = warnings.Length == 0 ? "" : warnings.Length + " warning(s): " + warnings[0] + (warnings.Length > 1 ? " See Logs for all warnings." : "");
            foreach (string warning in warnings) Log("Warning: " + warning);
        }
        private async Task<bool> Work(Action action, string success, bool replaceDnsDraft = false)
        {
            if (busy) return false; busy = true; toolbar.Enabled = false; tabs.Enabled = false; status.Text = "Working..."; UpdateActions();
            try { await Task.Run(action); status.Text = (active != null && active.IsRunning ? "Running (process only; VPN egress unverified). " : "Disconnected. ") + success; RefreshDocument(replaceDnsDraft); return true; }
            catch (Exception ex)
            {
                var transition = ex as TransitionException; if (transition != null) { active = transition.Active; if (!transition.Restored && !transition.FailedBeforeChange) appliedDocument = ""; }
                string message = Backend.ErrorMessage(ex.Message); Log(message);
                status.Text = transition != null && transition.Restored ? "Previous connection restored. Requested change failed." : (active != null && active.IsRunning ? "Existing connection remains running. Action failed." : "Action failed. See Logs.");
                UpdateState(); if (initialize) MessageBox.Show(this, message, "RouteBar", MessageBoxButtons.OK, MessageBoxIcon.Error); return false;
            }
            finally { toolbar.Enabled = true; tabs.Enabled = true; busy = false; UpdateActions(); }
        }
        private async Task<bool> SaveCandidate(Document candidate, string selectRule)
        {
            bool saved = await Work(() => { var normalized = services.Normalize(candidate); services.Save(normalized); document = normalized; savedDocument = Serialize(normalized); }, "Settings saved. Connect or Apply changes to use them.", true);
            if (saved && selectRule != null && rules.Items.ContainsKey(selectRule)) { rules.Items[selectRule].Selected = true; rules.Items[selectRule].EnsureVisible(); }
            return saved;
        }
        internal static string NextRuleName(IEnumerable<Rule> items)
        {
            var names = new HashSet<string>(items.Select(r => r.name), StringComparer.Ordinal); string name = "New rule"; int index = 2; while (names.Contains(name)) name = "New rule " + index++; return name;
        }
        internal static string ProfileTag(string file, IEnumerable<string> existing)
        {
            string stem = new string(Path.GetFileNameWithoutExtension(file).Select(c =>
                (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' ? c : '-').ToArray()).Trim('-');
            if (stem.Length == 0) stem = "vpn";
            if (!((stem[0] >= 'a' && stem[0] <= 'z') || (stem[0] >= 'A' && stem[0] <= 'Z')) || stem == "direct" || stem.StartsWith("vpnctl-", StringComparison.Ordinal)) stem = "vpn-" + stem;
            if (stem.Length > 64) stem = stem.Substring(0, 64);
            var names = new HashSet<string>(existing, StringComparer.Ordinal); string tag = stem; int n = 2;
            while (names.Contains(tag)) { string suffix = "-" + n++; tag = stem.Substring(0, Math.Min(stem.Length, 64 - suffix.Length)) + suffix; }
            return tag;
        }
        internal static string ProfileImportTag(Document candidate, string root, string file)
        {
            // The first import fills the unresolved vm1 preset; subsequent imports
            // receive unique names and never replace an existing working profile.
            return DefaultPreset.NeedsProfile(candidate, root) ? "vm1" : ProfileTag(file, candidate.vpns.Keys);
        }
        internal Task<Rule> ValidateRuleDraft(Rule rule, int index)
        {
            var candidate = CaptureDraft(); if (index >= 0) candidate.routing.rules[index] = rule; else candidate.routing.rules.Add(rule);
            int selected = index >= 0 ? index : candidate.routing.rules.Count - 1;
            return Task.Run(() => services.Normalize(candidate).routing.rules[selected]);
        }
        private async Task EditRule(bool edit)
        {
            int index = rules.SelectedIndices.Count > 0 ? rules.SelectedIndices[0] : -1; if (edit && index < 0) return; if (!edit) index = -1;
            using (var dialog = new RuleDialog(edit ? document.routing.rules[index] : new Rule { name = NextRuleName(document.routing.rules) }, Exits, r => ValidateRuleDraft(r, index)))
            {
                if (dialog.ShowDialog(this) != DialogResult.OK) return;
                var candidate = CaptureDraft(); if (edit) candidate.routing.rules[index] = dialog.Result; else candidate.routing.rules.Add(dialog.Result);
                await SaveCandidate(candidate, dialog.Result.name);
            }
        }
        private async Task ChangeRules(string change)
        {
            if (rules.SelectedIndices.Count == 0) return; int index = rules.SelectedIndices[0]; var candidate = CaptureDraft(); string selected = candidate.routing.rules[index].name;
            if (change == "remove") { if (MessageBox.Show(this, "Remove rule '" + selected + "'? This change will be saved; a running connection changes only after Apply changes.", "Remove rule", MessageBoxButtons.OKCancel, MessageBoxIcon.Question) != DialogResult.OK) return; candidate.routing.rules.RemoveAt(index); selected = candidate.routing.rules.Count == 0 ? null : candidate.routing.rules[Math.Min(index, candidate.routing.rules.Count - 1)].name; }
            else { int next = index + (change == "up" ? -1 : 1); if (next < 0 || next >= candidate.routing.rules.Count) return; var rule = candidate.routing.rules[index]; candidate.routing.rules.RemoveAt(index); candidate.routing.rules.Insert(next, rule); }
            await SaveCandidate(candidate, selected);
        }
        private async Task SaveDns() { await SaveCandidate(CaptureDraft(), null); }
        private async Task ImportVpn()
        {
            using (var dialog = new OpenFileDialog { Filter = "WireGuard profiles|*.conf", CheckFileExists = true })
            {
                if (dialog.ShowDialog(this) != DialogResult.OK) return; string file = dialog.FileName; var candidate = CaptureDraft();
                await Work(() => {
                    Store.PrivateDirectory(services.Root); string tag = ProfileImportTag(candidate, services.Root, file);
                    string target = Path.Combine(services.Root, "profile-" + Guid.NewGuid().ToString("N") + ".conf"); bool saved = false;
                    try
                    {
                        if (new FileInfo(file).Length > 128 * 1024) throw new IOException("WireGuard profile exceeds 128 KiB.");
                        Store.Write(target, File.ReadAllText(file)); candidate.vpns[tag] = new Vpn { wireguard_config = target };
                        var normalized = services.Normalize(candidate); using (var check = new Connection(normalized, services)) ShowWarnings(check.Warnings);
                        services.Save(normalized); document = normalized; savedDocument = Serialize(normalized); saved = true;
                    }
                    finally { if (!saved && File.Exists(target)) File.Delete(target); }
                }, "Profile imported. Add a rule or choose the exit as the default route.", true);
            }
        }
        private async Task RemoveVpn()
        {
            if (vpns.SelectedItems.Count == 0) return; string tag = vpns.SelectedItems[0].Name; var candidate = CaptureDraft();
            var references = candidate.routing.rules.Where(r => r.via == tag).Select(r => r.name).ToList(); if (candidate.dns.via == tag) references.Add("DNS exit"); if (candidate.routing.@default == tag) references.Add("default route");
            if (references.Count > 0) { MessageBox.Show(this, "Change these references before removing '" + tag + "':\n" + string.Join("\n", references), "Exit is in use"); return; }
            if (MessageBox.Show(this, "Remove exit '" + tag + "' from settings? Its imported profile remains on disk.", "Remove exit", MessageBoxButtons.OKCancel, MessageBoxIcon.Question) != DialogResult.OK) return;
            candidate.vpns.Remove(tag); await SaveCandidate(candidate, null);
        }
        private bool ConfirmReplace()
        {
            return Serialize(CaptureDraft()) == savedDocument || MessageBox.Show(this, "Importing replaces your unsaved settings. Continue?", "Unsaved settings", MessageBoxButtons.OKCancel, MessageBoxIcon.Question) == DialogResult.OK;
        }
        private async Task ImportConfig()
        {
            using (var dialog = new OpenFileDialog { Filter = "RouteBar configuration|*.yaml;*.yml;*.json", CheckFileExists = true })
                if (dialog.ShowDialog(this) == DialogResult.OK && ConfirmReplace()) { string file = dialog.FileName; await Work(() => { var candidate = services.Load(file); using (var snapshot = new Connection(candidate, services)) ShowWarnings(snapshot.Warnings); services.Save(candidate); document = candidate; savedDocument = Serialize(candidate); }, "Configuration imported. Apply changes to update an active connection.", true); }
        }
        private async void Export()
        {
            using (var dialog = new SaveFileDialog { Filter = "RouteBar JSON|*.json", FileName = "routebar-config.json" })
                if (dialog.ShowDialog(this) == DialogResult.OK)
                {
                    var draft = CaptureDraft(); string path = Path.GetFullPath(dialog.FileName);
                    await Work(() => { var normalized = services.Normalize(draft); if (normalized.vpns.Values.Any(v => string.Equals(path, Path.GetFullPath(v.wireguard_config), StringComparison.OrdinalIgnoreCase))) throw new IOException("Export must not overwrite a WireGuard profile."); Store.Write(path, Serialize(normalized)); }, "Visible settings exported (profile paths only; private keys are not included).");
                }
        }
        private async Task ValidateConfiguration()
        {
            var candidate = CaptureDraft(); await Work(() => { using (var snapshot = new Connection(candidate, services)) { ShowWarnings(snapshot.Warnings); Log("Visible rules, profiles and engine schema passed validation" + (snapshot.Warnings.Length == 0 ? "." : " with warnings.")); } }, "Visible settings validated without starting a VPN.");
        }
        private async Task Connect()
        {
            if (busy) return; var candidate = CaptureDraft();
            if (!Backend.IsAdmin)
            {
                bool ready = await Work(() => { var normalized = services.Normalize(candidate); using (var snapshot = new Connection(normalized, services)) ShowWarnings(snapshot.Warnings); services.Save(normalized); document = normalized; savedDocument = Serialize(normalized); }, "Settings validated. Requesting administrator authorization...", true);
                if (!ready) return;
                try
                {
                    string sid = WindowsIdentity.GetCurrent().User.Value;
                    Process.Start(new ProcessStartInfo(Application.ExecutablePath, "--connect --handoff " + Process.GetCurrentProcess().Id + " --user-sid " + Backend.Quote(sid)) { UseShellExecute = true, Verb = "runas", WorkingDirectory = AppDomain.CurrentDomain.BaseDirectory });
                    handoff = true; Close();
                }
                catch (System.ComponentModel.Win32Exception ex) { status.Text = ex.NativeErrorCode == 1223 ? "Authorization cancelled. Settings saved; not connected." : "Could not open administrator window: " + ex.Message; Log(status.Text); }
                catch (Exception ex) { status.Text = "Could not open administrator window."; Log(ex.Message); if (initialize) MessageBox.Show(this, ex.Message, "RouteBar"); }
                return;
            }
            await Work(() => {
                var normalized = services.Normalize(candidate); var next = new Connection(normalized, services); ShowWarnings(next.Warnings);
                try { services.Save(normalized); } catch { ConnectionTransaction.Cleanup(next, Log); throw; }
                document = normalized; savedDocument = Serialize(normalized);
                active = ConnectionTransaction.Replace(active, next, Log); appliedDocument = Serialize(normalized);
            }, "Connection process is running; verify the VPN egress separately.", true);
        }
        private async Task Disconnect()
        {
            await Work(() => { if (active != null) { var ended = active; ended.Stop(); active = null; appliedDocument = ""; ConnectionTransaction.Cleanup(ended, Log); } }, "Routing stopped.");
        }
        private async void OnClosing(object sender, FormClosingEventArgs e)
        {
            if (quitting) return; e.Cancel = true;
            if (busy) { status.Text = "Wait for the current operation before exiting."; return; }
            if (!handoff && Serialize(CaptureDraft()) != savedDocument)
            {
                var answer = MessageBox.Show(this, "Save your unsaved settings before exiting?", "Unsaved settings", MessageBoxButtons.YesNoCancel, MessageBoxIcon.Question);
                if (answer == DialogResult.Cancel) return;
                if (answer == DialogResult.Yes && !await SaveCandidate(CaptureDraft(), null)) return;
            }
            busy = true; Enabled = false; timer.Stop(); status.Text = "Disconnecting...";
            try { await Task.Run(() => { if (active != null) { var ended = active; ended.Stop(); active = null; ConnectionTransaction.Cleanup(ended, Log); } }); }
            catch (Exception ex) { busy = false; Enabled = true; if (initialize) timer.Start(); status.Text = "Could not disconnect. Keep RouteBar open and retry."; Log(ex.Message); if (initialize) MessageBox.Show(this, ex.Message, "Disconnect failed"); return; }
            tray.Visible = false; quitting = true; Close();
        }
        protected override void Dispose(bool disposing) { if (disposing) { timer.Dispose(); tray.Dispose(); } base.Dispose(disposing); }
    }
    internal sealed class InstanceLease : IDisposable
    {
        private readonly Mutex mutex;
        private readonly EventWaitHandle activation;
        private bool owned;
        private InstanceLease(Mutex instanceMutex, EventWaitHandle signal, bool acquired) { mutex = instanceMutex; activation = signal; owned = acquired; }
        internal static InstanceLease TryAcquire(string name)
        {
            var mutex = new Mutex(false, name); bool acquired;
            try { acquired = mutex.WaitOne(0); } catch (AbandonedMutexException) { acquired = true; }
            EventWaitHandle signal;
            try { signal = new EventWaitHandle(false, EventResetMode.AutoReset, name + ".Activate"); }
            catch { if (acquired) mutex.ReleaseMutex(); mutex.Dispose(); throw; }
            if (!acquired) { signal.Set(); signal.Dispose(); mutex.Dispose(); return null; }
            return new InstanceLease(mutex, signal, true);
        }
        internal bool ActivationRequested { get { return activation.WaitOne(0); } }
        public void Dispose() { activation.Dispose(); if (owned) { mutex.ReleaseMutex(); owned = false; } mutex.Dispose(); }
    }
    internal static class Program
    {
        [STAThread]
        private static int Main(string[] args)
        {
            if (args.Contains("--self-test")) return SelfTest.Run();
            Application.EnableVisualStyles(); Application.SetCompatibleTextRenderingDefault(false);
            try
            {
                int userIndex = Array.IndexOf(args, "--user-sid");
                if (userIndex >= 0 && (userIndex + 1 >= args.Length || args[userIndex + 1] != WindowsIdentity.GetCurrent().User.Value)) throw new IOException("Use the same Windows account for editing and administrator authorization.");
                int handoffIndex = Array.IndexOf(args, "--handoff");
                if (handoffIndex >= 0)
                {
                    int pid; if (handoffIndex + 1 >= args.Length || !int.TryParse(args[handoffIndex + 1], out pid)) throw new IOException("Invalid application handoff.");
                    try { using (var previous = Process.GetProcessById(pid)) { if (!previous.WaitForExit(30000)) throw new IOException("The previous RouteBar window did not close. Close it before opening this one."); } }
                    catch (ArgumentException) { }
                }
                string name = "Local\\RouteBar.Windows.UI." + WindowsIdentity.GetCurrent().User.Value;
                using (var lease = InstanceLease.TryAcquire(name))
                {
                    if (lease == null) return 0;
                    Application.Run(new MainForm(AppServices.Production(), true, args.Contains("--connect"), lease)); return 0;
                }
            }
            catch (UnauthorizedAccessException) { MessageBox.Show("RouteBar is already open in another privilege context. Use its existing window.", "RouteBar"); return 1; }
            catch (Exception ex) { MessageBox.Show(ex.Message, "RouteBar could not start", MessageBoxButtons.OK, MessageBoxIcon.Error); return 1; }
        }
    }
    internal static class SelfTest
    {
        internal static int Run()
        {
            try
            {
                if (Backend.Quote("C:\\space path\\") != "\"C:\\space path\\\\\"") throw new Exception("argument quoting");
                var doc = new Document(); doc.routing.rules.Add(new Rule { name = "Compound", via = "direct", match = new Selectors { process_names = new[] { "curl.exe" }, domains = new[] { "example.org" } } });
                if (Store.Clone(doc).routing.rules[0].match.domains[0] != "example.org") throw new Exception("document round trip");
                using (var form = new MainForm(new AppServices(Path.Combine(Path.GetTempPath(), "routebar-unused-ui-test"), a => { throw new InvalidOperationException("No backend calls permitted in construction test."); }), false)) { form.CreateControl(); if (form.Controls.Count == 0) throw new Exception("window controls"); }
                Console.WriteLine("Windows UI self-test passed."); return 0;
            }
            catch (Exception ex) { Console.Error.WriteLine(ex); return 1; }
        }
    }
}
