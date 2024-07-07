
rule Trojan_Win32_SmokeLoader_DK_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.DK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c7 33 c1 2b f0 89 44 24 14 8b c6 c1 e0 04 89 44 24 10 8b 44 24 2c 01 44 24 10 81 3d 90 02 04 be 01 00 00 8d 3c 2e 75 90 00 } //2
		$a_03_1 = {8b ce c1 e9 05 c7 05 90 02 04 19 36 6b ff c7 05 90 02 04 ff ff ff ff 89 4c 24 14 8b 44 24 24 01 44 24 14 81 3d 90 02 04 79 09 00 00 75 90 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}