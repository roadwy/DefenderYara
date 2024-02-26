
rule Backdoor_BAT_WebShell_GMQ_MTB{
	meta:
		description = "Backdoor:BAT/WebShell.GMQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 70 70 5f 67 6c 6f 62 61 6c 2e 61 73 61 78 2e 2d 72 6f 6d 6b 6f 5f 65 } //01 00  App_global.asax.-romko_e
		$a_01_1 = {41 70 70 5f 57 65 62 5f 68 69 6a 73 62 61 39 69 } //01 00  App_Web_hijsba9i
		$a_80_2 = {53 50 5f 6f 61 6d 65 74 68 6f 64 20 65 78 65 63 } //SP_oamethod exec  01 00 
		$a_80_3 = {6f 4a 69 79 6d } //oJiym  01 00 
		$a_80_4 = {42 61 63 6b 64 6f 6f 72 } //Backdoor  00 00 
	condition:
		any of ($a_*)
 
}