
rule Trojan_Win32_Tibs_GV{
	meta:
		description = "Trojan:Win32/Tibs.GV,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 d6 52 ac 86 90 03 01 01 c4 e0 ac 86 90 03 01 01 c4 e0 c1 90 03 01 01 e0 e8 90 01 01 c1 90 03 01 01 e0 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}