
rule Trojan_BAT_AgentTesla_LIC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LIC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 73 3a 2f 2f 62 75 79 73 72 69 6c 61 6e 6b 61 6e 2e 6c 6b 2f 6b 2f } //01 00  https://buysrilankan.lk/k/
		$a_01_1 = {52 65 76 65 72 73 65 } //01 00  Reverse
		$a_01_2 = {54 6f 41 72 72 61 79 } //01 00  ToArray
		$a_81_3 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00  DownloadData
		$a_01_4 = {49 6e 76 6f 6b 65 } //01 00  Invoke
		$a_01_5 = {47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 } //01 00  GetExportedTypes
		$a_01_6 = {47 65 74 4d 65 74 68 6f 64 } //01 00  GetMethod
		$a_01_7 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggerNonUserCodeAttribute
	condition:
		any of ($a_*)
 
}