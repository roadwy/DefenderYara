
rule Trojan_Win32_Raccoon_QA_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.QA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {33 75 f4 89 75 f0 8b 45 f0 01 05 90 01 04 8b 55 ec 2b fe 8b cf c1 e1 04 03 4d e4 03 d7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}