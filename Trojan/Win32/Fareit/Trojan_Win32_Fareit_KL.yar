
rule Trojan_Win32_Fareit_KL{
	meta:
		description = "Trojan:Win32/Fareit.KL,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {33 c0 8a 45 ef 33 84 8d e4 fb ff ff 88 06 90 05 10 01 90 [0-15] 46 ff 4d e4 0f 85 ?? ?? ff ff } //1
		$a_03_1 = {8d 85 e4 fb ff ff [0-10] 90 05 10 01 90 [0-10] 89 18 [0-20] 43 83 c0 04 81 fb 00 01 00 00 75 dc 8b 5d f0 81 fb ff 00 00 00 0f 8f a6 00 00 00 8d b4 9d e4 fb ff ff } //1
		$a_03_2 = {8b 84 bd e4 fb ff ff 89 06 [0-20] 8a c2 89 84 bd e4 fb ff ff 43 83 c6 04 81 fb 00 01 00 00 0f 85 ?? ?? ff ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}