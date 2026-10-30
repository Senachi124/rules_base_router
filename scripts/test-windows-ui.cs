// Offline application regression tests. Compile alongside RouteBar.cs with
// /main:RouteBar.Windows.UiRegressionTests; never launch the product entry point.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace RouteBar.Windows
{
    internal static class UiRegressionTests
    {
        private static readonly BindingFlags PrivateInstance = BindingFlags.Instance | BindingFlags.NonPublic;
        private static readonly List<string> Passed = new List<string>();
        private static string stateRoot;
        private static string controller;

        [STAThread]
        private static int Main(string[] args)
        {
            if (args.Length == 2 && args[0] == "--probe-instance")
            {
                // Probe only a test-created lease; never execute Program.Main.
                if (!args[1].StartsWith("Local\\RouteBar.UiRegression.", StringComparison.Ordinal)) return 2;
                using (var lease = InstanceLease.TryAcquire(args[1])) return lease == null ? 10 : 0;
            }
            if (args.Length != 1) { Console.Error.WriteLine("Expected the absolute bundled controller path."); return 2; }
            controller = Path.GetFullPath(args[0]);
            if (!File.Exists(controller)) { Console.Error.WriteLine("Build the controller before running UI regression tests."); return 2; }
            stateRoot = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "isolated-state");
            if (Directory.Exists(stateRoot)) { Console.Error.WriteLine("Refusing to reuse pre-existing test state."); return 2; }
            Store.PrivateDirectory(stateRoot);
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            int result = 0;
            try
            {
                Run("rollback survives candidate cleanup failure", RollbackSurvivesCleanupFailure);
                Run("successful replacement survives old cleanup failure", SuccessfulReplacementSurvivesCleanupFailure);
                Run("failed rollback reports no running connection", FailedRollbackIsReported);
                Run("visible DNS draft survives refresh and is validated", VisibleDnsDraft);
                Run("connection preparation failure is reported without launching", ConnectionPreparationFailure);
                Run("invalid and duplicate rule drafts survive validation", InvalidRuleRetention);
                Run("new rules receive distinct suggested names", UniqueRuleNames);
                Run("imported profile names are recognizable, safe and unique", ProfileNames);
                Run("rule selection survives consecutive reorder actions", SelectionSurvivesReorder);
                Run("real controller warnings reach the visible warning banner", ValidationWarningsAreVisible);
                Run("second process signals existing instance without owning it", SingletonAcrossProcesses);
                Run("editable fields expose accessible names", AccessibleFields);
                Run("rule actions fit minimum size at standard and larger font", RuleActionsFitMinimumSize);
                Run("minimum main window contains toolbar and DNS content width", MinimumMainWindow);
                Console.WriteLine("Windows UI regression tests passed: " + Passed.Count + ". No VPN or UAC was started.");
            }
            catch (Exception error)
            {
                Console.Error.WriteLine("FAIL: " + error);
                result = 1;
            }
            finally
            {
                // This process creates this one child of its private build directory.
                string parent = Path.GetFullPath(AppDomain.CurrentDomain.BaseDirectory).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
                string target = Path.GetFullPath(stateRoot);
                if (!target.StartsWith(parent, StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Unsafe test cleanup path.");
                try { if (Directory.Exists(target)) Directory.Delete(target, true); }
                catch (IOException error) { Console.Error.WriteLine("Test state cleanup failed: " + error.Message); result = 1; }
            }
            return result;
        }

        private static void Run(string name, Action action)
        {
            Console.WriteLine("RUN: " + name);
            action(); Passed.Add(name); Console.WriteLine("PASS: " + name);
        }
        private static void CreateUiHandles(Control control)
        {
            // Real windows create their handles on the STA before async actions.
            // Hidden test forms must do the same to make InvokeRequired reliable.
            Check(control.Handle != IntPtr.Zero, "Could not create UI control handle.");
            foreach (Control child in control.Controls) CreateUiHandles(child);
        }
        private static void Check(bool condition, string message)
        {
            if (!condition) throw new InvalidOperationException(message);
        }
        private static T Field<T>(object value, string name)
        {
            var field = value.GetType().GetField(name, PrivateInstance);
            if (field == null) throw new InvalidOperationException("Missing test field " + name);
            return (T)field.GetValue(value);
        }
        private static void Pump(Task task)
        {
            var deadline = Stopwatch.StartNew();
            while (!task.IsCompleted && deadline.Elapsed < TimeSpan.FromSeconds(30))
            {
                Application.DoEvents(); Thread.Sleep(10);
            }
            Check(task.IsCompleted, "Application task did not complete within 30 seconds.");
            task.GetAwaiter().GetResult();
        }
        private static string SafeCall(string[] args)
        {
            // A hard allowlist means a test cannot accidentally open a TUN or
            // trigger administrator authorization, even after product refactors.
            Check(args.Length > 0 && (args[0] == "config-inspect" || args[0] == "validate"), "Unsafe controller operation in UI test.");
            var info = new ProcessStartInfo(controller, string.Join(" ", args.Select(Backend.Quote))) {
                UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true,
                RedirectStandardError = true, StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8
            };
            using (var process = Process.Start(info))
            {
                var output = process.StandardOutput.ReadToEndAsync();
                var error = process.StandardError.ReadToEndAsync();
                if (!process.WaitForExit(25000)) { process.Kill(); process.WaitForExit(); throw new IOException("Schema controller timed out."); }
                Task.WaitAll(output, error);
                if (process.ExitCode != 0) throw new IOException(error.Result.Trim());
                return output.Result;
            }
        }
        private static Document Normalize(Document document)
        {
            string file = Path.Combine(stateRoot, Guid.NewGuid().ToString("N") + ".json");
            try
            {
                Store.Write(file, Store.Json().Serialize(document));
                return Store.Json().Deserialize<Document>(SafeCall(new[] { "config-inspect", "-c", file }));
            }
            finally { if (File.Exists(file)) File.Delete(file); }
        }
        private static AppServices Services() { return new AppServices(stateRoot, SafeCall); }

        private sealed class FakeConnection : IConnection
        {
            internal bool Running, FailStart, FailCleanup;
            internal int Starts, Stops, Cleanups;
            public bool IsRunning { get { return Running; } }
            public void Start(Action<string> log)
            {
                Starts++;
                if (FailStart) throw new IOException("Synthetic startup failure");
                Running = true;
            }
            public void Stop() { Stops++; Running = false; }
            public void Cleanup()
            {
                Cleanups++;
                if (FailCleanup) throw new IOException("Synthetic file sharing violation");
            }
        }
        private static void RollbackSurvivesCleanupFailure()
        {
            var previous = new FakeConnection { Running = true };
            var candidate = new FakeConnection { FailStart = true, FailCleanup = true };
            var messages = new List<string>();
            try
            {
                ConnectionTransaction.Replace(previous, candidate, messages.Add);
                throw new InvalidOperationException("Failed replacement was reported as successful.");
            }
            catch (TransitionException error)
            {
                Check(error.Restored, "Previous connection was not marked restored.");
                Check(object.ReferenceEquals(error.Active, previous), "Active connection did not remain the restored snapshot.");
            }
            Check(previous.IsRunning && previous.Starts == 1 && previous.Stops == 1, "Cleanup exception prevented restarting the previous connection.");
            Check(candidate.Cleanups == 1 && previous.Cleanups == 0, "Wrong snapshot cleanup during rollback.");
            Check(messages.Any(message => message.Contains("Synthetic file sharing violation")), "Cleanup failure was hidden.");
        }
        private static void SuccessfulReplacementSurvivesCleanupFailure()
        {
            var previous = new FakeConnection { Running = true, FailCleanup = true };
            var candidate = new FakeConnection();
            var messages = new List<string>();
            var active = ConnectionTransaction.Replace(previous, candidate, messages.Add);
            Check(object.ReferenceEquals(active, candidate) && candidate.IsRunning, "Successful candidate was lost when old snapshot cleanup failed.");
            Check(previous.Stops == 1 && previous.Cleanups == 1, "Previous connection was not stopped/cleaned once.");
            Check(messages.Any(message => message.Contains("Synthetic file sharing violation")), "Old snapshot cleanup failure was hidden.");
        }
        private static void FailedRollbackIsReported()
        {
            var previous = new FakeConnection { Running = true, FailStart = true };
            var candidate = new FakeConnection { FailStart = true };
            var messages = new List<string>();
            try
            {
                ConnectionTransaction.Replace(previous, candidate, messages.Add);
                throw new InvalidOperationException("Failed startup and failed restoration were reported as successful.");
            }
            catch (TransitionException error)
            {
                Check(!error.Restored, "Failed restoration was described as restored.");
                Check(error.Active == null || !error.Active.IsRunning, "Failed restoration exposes a running connection.");
            }
            Check(previous.Starts == 1 && !previous.IsRunning, "The previous snapshot was not attempted exactly once.");
            Check(candidate.Cleanups == 1, "The rejected candidate was not cleaned up.");
        }
        private static void VisibleDnsDraft()
        {
            string validatedServer = null;
            var services = new AppServices(stateRoot, args => {
                if (args.Length >= 3 && args[0] == "validate" && args[1] == "-c")
                    validatedServer = Store.Json().Deserialize<Document>(File.ReadAllText(args[2])).dns.server;
                return SafeCall(args);
            });
            using (var form = new MainForm(services, false))
            {
                CreateUiHandles(form);
                var server = Field<TextBox>(form, "dnsServer");
                server.Text = "9.9.9.9";
                Check(form.CaptureDraft().dns.server == "9.9.9.9", "CaptureDraft ignores the visible DNS server.");
                form.RefreshDocument();
                Check(server.Text == "9.9.9.9", "Refreshing unrelated UI erased the DNS draft.");
                Check(Normalize(form.CaptureDraft()).dns.server == "9.9.9.9", "The schema validator received stale saved DNS.");
                var validate = typeof(MainForm).GetMethod("ValidateConfiguration", PrivateInstance);
                Check(validate != null, "Validate action is missing.");
                Pump((Task)validate.Invoke(form, null));
                Check(validatedServer == "9.9.9.9", "The actual Validate action did not validate the visible DNS draft.");
                Check(server.Text == "9.9.9.9", "Successful validation erased the unsaved DNS draft.");
                server.Text = "https://bad-resolver.example";
                bool rejected = false;
                try { Normalize(form.CaptureDraft()); } catch (IOException) { rejected = true; }
                Check(rejected, "Invalid visible DNS was accepted because validation used the stored model.");
                form.RefreshDocument();
                Check(server.Text == "https://bad-resolver.example", "Validation/refresh erased an invalid DNS draft before correction.");
            }
        }
        private static void InvalidRuleRetention()
        {
            var existing = new Document();
            existing.routing.rules.Add(new Rule { name = "Existing", match = new Selectors { domains = new[] { "example.org" } } });
            using (var owner = new MainForm(Services(), false))
            {
                CreateUiHandles(owner);
                typeof(MainForm).GetField("document", PrivateInstance).SetValue(owner, existing);
                owner.RefreshDocument(true);
                using (var dialog = new RuleDialog(new Rule(), new[] { "direct" }, rule => owner.ValidateRuleDraft(rule, -1)))
                {
                CreateUiHandles(dialog);
                var name = Field<TextBox>(dialog, "name");
                var domains = Field<TextBox>(dialog, "domains");
                name.Text = "Unique"; domains.Text = "https://invalid.example";
                var first = dialog.TrySave(); Pump(first);
                Check(!first.Result && !dialog.IsDisposed && dialog.DialogResult != DialogResult.OK, "Invalid rule closed the editor.");
                Check(name.Text == "Unique" && domains.Text == "https://invalid.example", "Invalid input was lost.");
                Check(!string.IsNullOrWhiteSpace(dialog.ValidationMessage), "Rule validation failure has no visible explanation.");
                name.Text = "Existing"; domains.Text = "example.net";
                var duplicate = dialog.TrySave(); Pump(duplicate);
                Check(!duplicate.Result && name.Text == "Existing" && domains.Text == "example.net", "Duplicate name was accepted or lost its editable draft.");
                name.Text = "Unique corrected";
                var corrected = dialog.TrySave(); Pump(corrected);
                Check(corrected.Result && dialog.Result.name == "Unique corrected", "Correcting the rule did not allow saving.");
                }
            }
        }
        private static void ConnectionPreparationFailure()
        {
            int calls = 0;
            var services = new AppServices(stateRoot, args => { calls++; throw new IOException("Synthetic preparation failure"); });
            using (var form = new MainForm(services, false))
            {
                CreateUiHandles(form);
                Pump((Task)typeof(MainForm).GetMethod("Connect", PrivateInstance).Invoke(form, null));
                Check(calls == 1, "Connect continued after preparation failed.");
                Check(Field<IConnection>(form, "active") == null, "Preparation failure created an active connection.");
                Check(!Field<bool>(form, "busy"), "Preparation failure left the UI busy.");
                Check(Field<TextBox>(form, "logs").Text.Contains("Synthetic preparation failure"), "Preparation failure was not reported.");
                Check(Field<Control>(form, "toolbar").Enabled && Field<TabControl>(form, "tabs").Enabled, "Preparation failure left controls disabled.");
            }
        }
        private static void UniqueRuleNames()
        {
            var rules = new List<Rule>();
            for (int index = 0; index < 4; index++)
            {
                string name = MainForm.NextRuleName(rules);
                Check(!string.IsNullOrWhiteSpace(name) && !rules.Any(rule => rule.name == name), "A suggested rule name collides with an existing rule.");
                rules.Add(new Rule { name = name });
            }
        }
        private static void ProfileNames()
        {
            Check(MainForm.ProfileTag("vm1.conf", new string[0]) == "vm1", "Recognizable filename stem was lost.");
            Check(MainForm.ProfileTag("vm1.conf", new[] { "vm1" }) == "vm1-2", "Repeated imports collide.");
            var used = new List<string>();
            foreach (string file in new[] { "direct.conf", "vpnctl-test.conf", "123.conf", "香港.conf", new string('a', 90) + ".conf", new string('a', 90) + ".conf" })
            {
                string tag = MainForm.ProfileTag(file, used);
                Check(System.Text.RegularExpressions.Regex.IsMatch(tag, "^[A-Za-z][A-Za-z0-9_-]{0,63}$"), "Imported tag violates schema syntax: " + tag);
                Check(tag != "direct" && !tag.StartsWith("vpnctl-", StringComparison.Ordinal), "Imported tag occupies a reserved namespace.");
                Check(!used.Contains(tag), "Long imported profile names collide.");
                used.Add(tag);
            }
        }
        private static void ValidationWarningsAreVisible()
        {
            var document = new Document();
            string missing = Path.Combine(stateRoot, "missing-application.exe");
            document.routing.rules.Add(new Rule { name = "Missing app", match = new Selectors { apps = new[] { missing } } });
            using (var snapshot = new Connection(document, Services()))
                Check(snapshot.Warnings.Any(warning => warning.Contains("missing-application.exe")), "The actual controller warning was discarded by the snapshot.");
            using (var form = new MainForm(Services(), false))
            {
                CreateUiHandles(form);
                typeof(MainForm).GetField("document", PrivateInstance).SetValue(form, document);
                form.RefreshDocument(true);
                Pump((Task)typeof(MainForm).GetMethod("ValidateConfiguration", PrivateInstance).Invoke(form, null));
                Check(Field<Label>(form, "warningSummary").Text.Contains("missing-application.exe"), "Successful validation did not surface the missing-application warning.");
            }
        }
        private static int ProbeLease(string name)
        {
            var info = new ProcessStartInfo(Assembly.GetExecutingAssembly().Location, "--probe-instance " + Backend.Quote(name)) {
                UseShellExecute = false, CreateNoWindow = true
            };
            using (var process = Process.Start(info))
            {
                if (!process.WaitForExit(10000)) { process.Kill(); process.WaitForExit(); throw new IOException("Instance probe timed out."); }
                return process.ExitCode;
            }
        }
        private static void SingletonAcrossProcesses()
        {
            string name = "Local\\RouteBar.UiRegression." + Guid.NewGuid().ToString("N");
            using (var lease = InstanceLease.TryAcquire(name))
            {
                Check(lease != null, "The first test instance could not acquire its lease.");
                Check(ProbeLease(name) == 10, "A second process acquired the live instance lease.");
                Check(lease.ActivationRequested, "The rejected second instance did not signal the owner.");
                Check(!lease.ActivationRequested, "The activation signal was not consumed.");
            }
            Check(ProbeLease(name) == 0, "The instance lease was not available after normal disposal.");
        }
        private static IEnumerable<Control> Descendants(Control control)
        {
            foreach (Control child in control.Controls) { yield return child; foreach (var nested in Descendants(child)) yield return nested; }
        }
        private static void SelectionSurvivesReorder()
        {
            using (var form = new MainForm(Services(), false))
            {
                CreateUiHandles(form);
                var document = new Document();
                foreach (string name in new[] { "First", "Second", "Third" })
                    document.routing.rules.Add(new Rule { name = name, match = new Selectors { domains = new[] { "example.org" } } });
                typeof(MainForm).GetField("document", PrivateInstance).SetValue(form, document);
                form.RefreshDocument(true);
                var rules = Field<ListView>(form, "rules");
                Check(rules.Handle != IntPtr.Zero, "Rule list handle was not created."); // Selection is native state.
                rules.Items[2].Selected = true;
                rules.Items[2].Focused = true;
                var move = typeof(MainForm).GetMethod("ChangeRules", PrivateInstance);
                Check(move != null, "Reorder action is missing.");
                Pump((Task)move.Invoke(form, new object[] { "up" }));
                Check(rules.SelectedItems.Count == 1 && rules.SelectedItems[0].SubItems[1].Text == "Third", "Selection was lost after the first move.");
                Pump((Task)move.Invoke(form, new object[] { "up" }));
                Check(rules.Items[0].SubItems[1].Text == "Third" && rules.SelectedIndices.Count == 1 && rules.SelectedIndices[0] == 0, "Consecutive move operated on the wrong rule or required reselection.");
            }
        }
        private static void AccessibleFields()
        {
            using (var form = new MainForm(Services(), false))
            using (var dialog = new RuleDialog(new Rule(), new[] { "direct" }))
            {
                foreach (var field in Descendants(form).Concat(Descendants(dialog)).Where(control => control is ComboBox || (control is TextBox && !((TextBox)control).ReadOnly)))
                    Check(!string.IsNullOrWhiteSpace(field.AccessibleName), "Editable control has no accessible name: " + field.GetType().Name);
            }
        }
        private static void RuleActionsFitMinimumSize()
        {
            foreach (float fontSize in new[] { 9F, 14F })
            using (var dialog = new RuleDialog(new Rule(), new[] { "direct" }))
            {
                dialog.Font = new Font(dialog.Font.FontFamily, fontSize);
                dialog.Size = dialog.MinimumSize;
                CreateUiHandles(dialog);
                foreach (var control in Descendants(dialog).Reverse()) control.PerformLayout();
                dialog.PerformLayout();
                foreach (var button in Descendants(dialog).OfType<Button>())
                {
                    Check(button.Handle != IntPtr.Zero, "Rule button handle was not created.");
                    Rectangle bounds = button.Bounds;
                    Control parent = button.Parent;
                    while (parent != null)
                    {
                        Check(parent.ClientRectangle.Contains(bounds), "Rule button is clipped at minimum window size: " + button.Text + "; ancestor=" + parent.GetType().Name + "; button=" + bounds + "; viewport=" + parent.ClientRectangle);
                        bounds.Offset(parent.Left, parent.Top);
                        parent = parent.Parent;
                    }
                }
            }
        }
        private static void MinimumMainWindow()
        {
            using (var form = new MainForm(Services(), false))
            {
                form.Size = form.MinimumSize;
                var tabs = Field<TabControl>(form, "tabs");
                tabs.SelectedIndex = 2;
                CreateUiHandles(form);
                form.PerformLayout();
                foreach (var control in Descendants(form)) control.PerformLayout();
                var root = form.Controls.OfType<TableLayoutPanel>().Single();
                foreach (Control child in root.Controls)
                    Check(root.ClientRectangle.Contains(child.Bounds), "Main content is clipped at minimum window size: " + child.GetType().Name + " " + child.Bounds);
                var toolbar = Field<FlowLayoutPanel>(form, "toolbar");
                foreach (Button button in toolbar.Controls.OfType<Button>())
                    Check(toolbar.ClientRectangle.Contains(button.Bounds), "Toolbar action is clipped at minimum window size: " + button.Text);
                var page = tabs.TabPages[2];
                var dns = page.Controls.OfType<TableLayoutPanel>().Single();
                Check(page.AutoScroll, "DNS content has no scrolling container at minimum size.");
                Check(dns.Left >= 0 && dns.Right <= page.ClientSize.Width, "DNS content exceeds the available width.");
                foreach (Control child in dns.Controls)
                    Check(dns.ClientRectangle.Contains(child.Bounds), "DNS field, action or explanation is clipped within its content panel: " + child.Text);
                var save = Descendants(dns).OfType<Button>().Single(button => button.Text == "Save DNS and default");
                Check(save.Parent.ClientRectangle.Contains(save.Bounds), "DNS save action is clipped inside its row.");
                // These are offscreen content bounds. Actual scrolling and monitor
                // DPI remain interactive acceptance checks, not claims of this test.
            }
        }
    }
}
