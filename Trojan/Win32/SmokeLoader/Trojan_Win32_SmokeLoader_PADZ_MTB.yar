
rule Trojan_Win32_SmokeLoader_PADZ_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.PADZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 45 f8 89 45 f4 8d 45 f4 50 e8 b8 ff ff ff 83 c4 04 8b 45 f4 83 c0 64 89 45 f8 83 6d f8 64 8a 4d f8 30 0c 1e 83 ff 0f 75 22 } //1
		$a_03_1 = {69 c0 fd 43 03 00 81 3d ?? ?? ?? ?? 9e 13 00 00 a3 f8 21 34 02 75 0f } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}