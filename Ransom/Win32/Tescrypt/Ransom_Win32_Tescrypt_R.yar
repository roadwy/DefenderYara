
rule Ransom_Win32_Tescrypt_R{
	meta:
		description = "Ransom:Win32/Tescrypt.R,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {0f b7 c0 c1 c1 07 83 c2 02 33 c8 0f b7 02 66 85 c0 75 ed 81 f9 8e fe 1f 4b 74 27 } //1
		$a_03_1 = {68 5c 01 00 00 68 ?? ?? ?? ?? 53 c7 85 ?? ?? ff ff 00 00 00 00 ff 15 ?? ?? ?? ?? 85 c0 74 a8 } //1
		$a_03_2 = {68 f0 9a b8 6f 6a 01 6a 00 e8 ?? ?? ?? ?? 8b 4d 08 83 c4 0c 6a 00 6a 00 6a 00 51 6a 00 6a 00 ff d0 } //1
		$a_01_3 = {68 bc 02 00 00 6a 00 6a 00 c7 06 00 00 00 00 6a 00 66 0f ef c0 66 0f d6 46 04 6a 12 c7 46 0c 00 00 00 00 ff 15 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}