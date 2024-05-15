
rule Trojan_Win32_ShellcodeRunner_RP_MTB{
	meta:
		description = "Trojan:Win32/ShellcodeRunner.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 61 6e 73 68 6f 75 77 6f 72 6b 5f 64 65 66 61 75 6c 74 5f 61 73 70 78 } //01 00  hanshouwork_default_aspx
		$a_01_1 = {68 61 6e 73 68 6f 75 77 6f 72 6b 5f 6c 69 73 74 73 76 69 65 77 5f 61 73 70 78 } //01 00  hanshouwork_listsview_aspx
		$a_01_2 = {41 70 70 5f 67 6c 6f 62 61 6c 2e 61 73 61 78 2e 6e 76 71 74 61 68 36 6b } //01 00  App_global.asax.nvqtah6k
		$a_01_3 = {43 72 65 61 74 65 5f 41 53 50 5f 68 61 6e 73 68 6f 75 77 6f 72 6b 5f 64 65 66 61 75 6c 74 5f 61 73 70 78 } //00 00  Create_ASP_hanshouwork_default_aspx
	condition:
		any of ($a_*)
 
}