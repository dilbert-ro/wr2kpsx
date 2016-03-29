using System;
using System.Linq;
using System.Xml;
using System.Xml.Linq;
using KeePassLib;
using KeePassLib.Serialization;
using KeePassLib.Interfaces;
using KeePassLib.Keys;
using CommandLine;
using CommandLine.Text;


namespace wr2kpsx
{
	class MainClass
	{
		public static void Main(string[] args)
		{
			(new MainClass()).Run(args);
		}

		private void Run(string[] args)
		{
			var options = new Options();
			if (!CommandLine.Parser.Default.ParseArguments(args, options))
			{
				return;
			}

			PrintMsg("Start importing: " + options.InputFile);

			try
			{
				this.verbose = options.Verbose;
				this.importBookmarks = options.ImportBookmarks;
				ImportXML(options.InputFile, options.KeePassPwd);
			}
			catch (Exception ex)
			{
				PrintMsg(ex.Message);
				Environment.Exit(1);

				return;
			}
		}

		private void PrintMsg(string msg)
		{
			if (this.verbose)
			{
				Console.WriteLine(msg);
			}
		}

		void ImportXML(string xmlFile, string pwd)
		{
			// Create a new Keepass database.
			var kdbxPath = xmlFile + ".kdbx";
			var ioConnInfo = new IOConnectionInfo { Path = kdbxPath };
			var compKey = new CompositeKey();
			compKey.AddUserKey(new KcpPassword(pwd));

			var kpdb = new KeePassLib.PwDatabase();
			kpdb.New(ioConnInfo, compKey);

			PrintMsg("Importing to: " + kdbxPath);

			try
			{
				// Read the XML file.
				XDocument xdoc = XDocument.Load(xmlFile);

				///////////////////////////////////////////////////////////////////////////
				PrintMsg("Logins...");
				var logins = from lgn in xdoc.Descendants("login")
					select new {
					Name  = lgn.Attribute("name").Value,
					Url   = lgn.Attribute("site").Value,
					User  = lgn.Attribute("user").Value,
					Pwd   = lgn.Attribute("password").Value,
					User2 = lgn.Attribute("user2").Value,
					Pwd2  = lgn.Attribute("password2").Value,
					Notes = lgn.Value
				};

				int doubleUserAccount = 0;
				var accountsGroup = kpdb.RootGroup.FindCreateGroup("Accounts", true);
				foreach (var lgn in logins)
				{
					var login = new PwEntry(true, true);
					login.Strings.Set("Title",    new KeePassLib.Security.ProtectedString(true, lgn.Name));
					login.Strings.Set("Notes",    new KeePassLib.Security.ProtectedString(true, lgn.Notes));
					login.Strings.Set("URL",      new KeePassLib.Security.ProtectedString(true, lgn.Url));
					login.Strings.Set("UserName", new KeePassLib.Security.ProtectedString(true, lgn.User));
					login.Strings.Set("Password", new KeePassLib.Security.ProtectedString(true, lgn.Pwd));

					accountsGroup.AddEntry(login, true);

					if (!String.IsNullOrWhiteSpace(lgn.User2) ||
						!String.IsNullOrWhiteSpace(lgn.Pwd2))
					{
						doubleUserAccount++;
					}
				}

				PrintMsg(String.Format("{0} accounts imported, {1} accounts with 2 credentials", logins.Count(), doubleUserAccount));

				///////////////////////////////////////////////////////////////////////////
				PrintMsg("Notes...");
				var safeNotes = from sn in xdoc.Descendants("note")
					select new {
					Name = sn.Attribute("name").Value,
					Text = sn.Value
				};

				var notesGroup = kpdb.RootGroup.FindCreateGroup("Notes", true);
				foreach (var sn in safeNotes)
				{
					var note = new PwEntry(true, true);
					note.Strings.Set("Title", new KeePassLib.Security.ProtectedString(true, sn.Name));
					note.Strings.Set("Notes", new KeePassLib.Security.ProtectedString(true, sn.Text));

					notesGroup.AddEntry(note, true);
				}

				PrintMsg(String.Format("{0} notes imported", safeNotes.Count()));

				///////////////////////////////////////////////////////////////////////////
				if (this.importBookmarks)
				{
					PrintMsg("Bookmarks...");
					var bookmarks = from bm in xdoc.Descendants("bookmark")
						select new {
						Url = bm.Attribute("url").Value,
						Name = bm.Value
					};

					var bookmarksGroup = kpdb.RootGroup.FindCreateGroup("Bookmarks", true);
					foreach (var b in bookmarks)
					{
						var bookmark = new PwEntry(true, true);
						bookmark.Strings.Set("Title", new KeePassLib.Security.ProtectedString(true, b.Name));
						bookmark.Strings.Set("URL", new KeePassLib.Security.ProtectedString(true, b.Url));

						bookmarksGroup.AddEntry(bookmark, true);
					}

					PrintMsg(String.Format("{0} bookmarks imported", bookmarks.Count()));
				}
			}
			finally
			{
				kpdb.Save(null);
				kpdb.Close();
				kpdb = null;
			}
		}

		private bool verbose = true;
		private bool importBookmarks = false;
	}


	internal class Options
	{
		[Option('r', "read", Required = true, HelpText = "Input XML file to be imported.")]
		public string InputFile { get; set; }

		[Option('p', "password", Required = false, HelpText = "Set password on kbdx database.")]
		public string KeePassPwd { get; set; }

		[Option('b', "bookmakrs", DefaultValue = false, HelpText = "Import bookmarks.")]
		public bool ImportBookmarks { get; set; }

		[Option('v', "verbose", DefaultValue = true, HelpText = "Prints all messages to standard output.")]
		public bool Verbose { get; set; }

		[ParserState]
		public IParserState LastParserState { get; set; }

		[HelpOption]
		public string GetUsage()
		{
			return HelpText.AutoBuild(this,	(HelpText current) => HelpText.DefaultParsingErrorsHandler(this, current));
		}
	}
}
