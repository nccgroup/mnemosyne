﻿//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool.
//     Runtime Version:4.0.30319.42000
//
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace MemoryScanner.Resources {
    using System;
    
    
    /// <summary>
    ///   A strongly-typed resource class, for looking up localized strings, etc.
    /// </summary>
    // This class was auto-generated by the StronglyTypedResourceBuilder
    // class via a tool like ResGen or Visual Studio.
    // To add or remove a member, edit your .ResX file then rerun ResGen
    // with the /str option, or rebuild your VS project.
    [global::System.CodeDom.Compiler.GeneratedCodeAttribute("System.Resources.Tools.StronglyTypedResourceBuilder", "4.0.0.0")]
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute()]
    [global::System.Runtime.CompilerServices.CompilerGeneratedAttribute()]
    internal class MessageStrings {
        
        private static global::System.Resources.ResourceManager resourceMan;
        
        private static global::System.Globalization.CultureInfo resourceCulture;
        
        [global::System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1811:AvoidUncalledPrivateCode")]
        internal MessageStrings() {
        }
        
        /// <summary>
        ///   Returns the cached ResourceManager instance used by this class.
        /// </summary>
        [global::System.ComponentModel.EditorBrowsableAttribute(global::System.ComponentModel.EditorBrowsableState.Advanced)]
        internal static global::System.Resources.ResourceManager ResourceManager {
            get {
                if (object.ReferenceEquals(resourceMan, null)) {
                    global::System.Resources.ResourceManager temp = new global::System.Resources.ResourceManager("MemoryScanner.Resources.MessageStrings", typeof(MessageStrings).Assembly);
                    resourceMan = temp;
                }
                return resourceMan;
            }
        }
        
        /// <summary>
        ///   Overrides the current thread's CurrentUICulture property for all
        ///   resource lookups using this strongly typed resource class.
        /// </summary>
        [global::System.ComponentModel.EditorBrowsableAttribute(global::System.ComponentModel.EditorBrowsableState.Advanced)]
        internal static global::System.Globalization.CultureInfo Culture {
            get {
                return resourceCulture;
            }
            set {
                resourceCulture = value;
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Working on processID {0} : {1}.
        /// </summary>
        internal static string ProcessIdMessage {
            get {
                return ResourceManager.GetString("ProcessIdMessage", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Starting search for &quot;{0}&quot; and sending output to file {1} with delay of {2} and width of {3}.
        /// </summary>
        internal static string SearchStartMessageForFile {
            get {
                return ResourceManager.GetString("SearchStartMessageForFile", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Starting search for &quot;{0}&quot; and sending output to {1}:{2} with delay of {3} and width of {4}.
        /// </summary>
        internal static string SearchStartMessageForSocket {
            get {
                return ResourceManager.GetString("SearchStartMessageForSocket", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Starting search for &quot;{0}&quot; and sending output to stdio with delay of {1} and width of {2}.
        /// </summary>
        internal static string SearchStartMessageForStandardIO {
            get {
                return ResourceManager.GetString("SearchStartMessageForStandardIO", resourceCulture);
            }
        }
    }
}
