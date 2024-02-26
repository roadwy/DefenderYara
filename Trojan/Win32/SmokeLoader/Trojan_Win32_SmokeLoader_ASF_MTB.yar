
rule Trojan_Win32_SmokeLoader_ASF_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.ASF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 f5 31 74 24 10 8b 44 24 10 29 44 24 14 c7 44 24 18 00 00 00 00 8b 44 24 38 01 44 24 18 2b 5c 24 18 ff 4c 24 20 0f } //01 00 
		$a_03_1 = {03 c3 33 d1 33 d0 2b fa 8b cf c1 e1 04 c7 05 90 01 04 00 00 00 00 89 4c 24 10 8b 44 24 2c 01 44 24 10 81 3d 90 01 04 be 01 00 00 8d 2c 3b 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}