
rule Trojan_Win32_SmokeLoader_VKL_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.VKL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c7 c1 e8 90 01 01 8d 34 2f c7 05 90 01 08 c7 05 90 01 08 89 44 24 10 8b 44 24 90 01 01 01 44 24 10 8b 0d 90 01 04 81 f9 90 01 04 75 90 01 01 8d 4c 24 30 51 6a 00 ff 15 90 01 04 8b 0d cc b7 49 00 8b 54 24 10 8b 44 24 90 01 01 33 d6 33 c2 2b d8 81 f9 90 01 04 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}