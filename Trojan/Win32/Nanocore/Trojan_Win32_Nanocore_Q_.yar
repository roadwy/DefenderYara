
rule Trojan_Win32_Nanocore_Q_{
	meta:
		description = "Trojan:Win32/Nanocore.Q!!Nanocore.gen!MTB,SIGNATURE_TYPE_ARHSTR_EXT,08 00 08 00 0a 00 00 01 00 "
		
	strings :
		$a_81_0 = {4e 61 6e 6f 43 6f 72 65 20 43 6c 69 65 6e 74 2e 65 78 65 } //01 00  NanoCore Client.exe
		$a_81_1 = {4e 61 6e 6f 43 6f 72 65 2e 43 6c 69 65 6e 74 50 6c 75 67 69 6e 48 6f 73 74 } //01 00  NanoCore.ClientPluginHost
		$a_81_2 = {53 75 72 76 65 69 6c 6c 61 6e 63 65 45 78 43 6c 69 65 6e 74 50 6c 75 67 69 6e 2e 64 6c 6c } //01 00  SurveillanceExClientPlugin.dll
		$a_81_3 = {42 61 73 65 43 6f 6d 6d 61 6e 64 } //01 00  BaseCommand
		$a_81_4 = {46 69 6c 65 43 6f 6d 6d 61 6e 64 } //01 00  FileCommand
		$a_81_5 = {50 6c 75 67 69 6e 43 6f 6d 6d 61 6e 64 } //01 00  PluginCommand
		$a_81_6 = {44 6e 73 52 65 63 6f 72 64 } //01 00  DnsRecord
		$a_81_7 = {41 64 64 48 6f 73 74 45 6e 74 72 79 } //01 00  AddHostEntry
		$a_81_8 = {44 69 73 61 62 6c 65 50 72 6f 74 65 63 74 69 6f 6e } //01 00  DisableProtection
		$a_81_9 = {52 65 73 74 6f 72 65 50 72 6f 74 65 63 74 69 6f 6e } //00 00  RestoreProtection
	condition:
		any of ($a_*)
 
}