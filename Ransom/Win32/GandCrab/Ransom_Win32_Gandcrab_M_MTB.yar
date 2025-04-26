
rule Ransom_Win32_Gandcrab_M_MTB{
	meta:
		description = "Ransom:Win32/Gandcrab.M!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {01 4c cd 21 54 68 69 73 20 90 19 01 01 70 90 19 01 01 72 90 19 01 01 6f 90 19 01 01 67 90 19 01 01 72 90 19 01 01 61 6d 20 63 61 6e 6e 6f 74 20 62 65 20 72 75 6e 20 69 6e 20 44 4f 53 20 6d 6f 64 65 } //1
		$a_02_1 = {8b 4d c4 03 4d fc 0f be 19 e8 ?? ?? ff ff 33 d8 8b 55 c4 03 55 fc 88 1a eb ?? 5b 8b e5 5d c3 } //1
		$a_02_2 = {55 8b ec 81 ec 00 08 00 00 a1 ?? ?? ?? 00 69 c0 ?? ?? ?? ?? 05 ?? ?? ?? ?? a3 ?? ?? ?? 00 [0-50] a1 ?? ?? ?? 00 c1 e8 10 25 ff 7f 00 00 8b e5 5d c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}