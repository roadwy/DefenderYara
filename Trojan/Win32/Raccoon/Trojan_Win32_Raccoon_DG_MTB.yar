
rule Trojan_Win32_Raccoon_DG_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.DG!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {c1 e0 04 03 45 dc 89 45 fc 8b 45 f8 03 c3 89 45 ec 8b c3 c1 e8 05 03 45 d8 89 45 f4 8b 45 ec 31 45 fc } //00 00 
	condition:
		any of ($a_*)
 
}