
rule Backdoor_BAT_WebShell_GMP_MTB{
	meta:
		description = "Backdoor:BAT/WebShell.GMP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 70 70 5f 67 6c 6f 62 61 6c 2e 61 73 61 78 2e 73 76 77 6e 7a 6a 6b 6a } //01 00  App_global.asax.svwnzjkj
		$a_80_1 = {42 61 63 6b 64 6f 6f 72 } //Backdoor  01 00 
		$a_80_2 = {75 58 65 76 4e } //uXevN  01 00 
		$a_01_3 = {43 72 65 61 74 65 5f 41 53 50 5f 6d 65 6d 62 65 72 73 65 72 76 69 63 65 5f 61 6a 61 78 5f 34 30 34 5f 61 73 70 78 } //01 00  Create_ASP_memberservice_ajax_404_aspx
		$a_80_4 = {53 50 5f 6f 61 6d 65 74 68 6f 64 20 65 78 65 63 } //SP_oamethod exec  00 00 
	condition:
		any of ($a_*)
 
}