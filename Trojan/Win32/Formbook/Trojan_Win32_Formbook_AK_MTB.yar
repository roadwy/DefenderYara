
rule Trojan_Win32_Formbook_AK_MTB{
	meta:
		description = "Trojan:Win32/Formbook.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 06 00 "
		
	strings :
		$a_01_0 = {81 f2 1f 96 00 00 43 2d 10 03 00 00 81 f1 b2 b1 00 00 b9 92 1b 00 00 5a 81 e2 d7 78 01 00 05 76 8e 00 00 f7 d3 4a 81 e1 40 9c 00 00 05 76 d6 00 00 81 fa 1f 96 00 00 74 14 } //00 00 
	condition:
		any of ($a_*)
 
}