
rule Trojan_Win32_Raccoon_NNW_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.NNW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c8 33 d2 8b 45 f4 f7 f1 8a 0e 8b 45 f8 32 8a 90 01 04 88 0c 30 8b 4d f4 41 46 89 4d f4 83 f9 40 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}