
rule Trojan_Win32_SmokeLoader_CC_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.CC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_03_0 = {8b 44 24 10 33 44 24 2c c7 05 90 02 04 00 00 00 00 2b d0 8b ca c1 e1 04 89 44 24 10 89 4c 24 2c 8b 44 24 20 01 44 24 2c 8b c2 c1 e8 05 03 c5 03 fa 33 f8 8b 44 24 2c 33 c7 2b f0 68 b9 79 37 9e 8d 44 24 18 50 c7 05 90 02 04 19 36 6b ff c7 05 90 02 04 ff ff ff ff e8 90 02 04 4b 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}