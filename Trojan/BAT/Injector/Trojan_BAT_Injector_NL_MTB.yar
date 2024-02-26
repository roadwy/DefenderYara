
rule Trojan_BAT_Injector_NL_MTB{
	meta:
		description = "Trojan:BAT/Injector.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 06 00 00 04 00 "
		
	strings :
		$a_81_0 = {61 79 65 6e 64 6f 6e 6a 65 61 6e 73 2e 63 6f 6d 2f 5a 76 65 6a 68 6f 6f 73 72 67 2e 76 64 66 } //01 00  ayendonjeans.com/Zvejhoosrg.vdf
		$a_80_1 = {44 79 6e 61 6d 69 63 49 6e 76 6f 6b 65 } //DynamicInvoke  01 00 
		$a_80_2 = {49 6e 76 6f 6b 65 } //Invoke  01 00 
		$a_80_3 = {48 74 6d 6c 44 65 63 6f 64 65 } //HtmlDecode  01 00 
		$a_80_4 = {49 6e 76 6f 6b 65 43 6f 64 65 } //InvokeCode  01 00 
		$a_80_5 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //DebuggerHiddenAttribute  00 00 
	condition:
		any of ($a_*)
 
}