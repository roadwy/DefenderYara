
rule Trojan_WinNT_Tibs_gen_D{
	meta:
		description = "Trojan:WinNT/Tibs.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 83 c4 04 52 c3 } //01 00 
		$a_01_1 = {0f 20 c6 89 f7 0f ba fe 10 0f 22 c6 c3 } //00 00 
	condition:
		any of ($a_*)
 
}