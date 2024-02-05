
rule Trojan_Win32_Zenpak_CAU_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.CAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {8b 7d e8 8a 1c 0f 8b 7d e0 32 1c 37 8b 75 e4 88 1c 0e c7 05 90 02 04 33 00 00 00 81 c1 01 00 00 00 8b 75 f0 39 f1 8b 75 d0 89 4d ec 89 75 dc 89 55 d8 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}