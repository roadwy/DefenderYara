
rule Trojan_Win32_Alureon_GG{
	meta:
		description = "Trojan:Win32/Alureon.GG,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_03_0 = {ff 70 54 57 53 e8 90 01 04 0f b7 70 06 0f b7 48 14 8d 4c 01 18 85 f6 7e 5d 90 00 } //1
		$a_03_1 = {c6 04 38 b8 b9 ff e0 00 00 66 89 4c 38 05 8b 06 8b 3d 90 01 04 c6 00 fa ff 76 08 ff 36 e8 90 01 04 59 59 90 00 } //1
		$a_03_2 = {8b 5e 0c 8b 09 ff 76 08 03 d9 53 ff 75 90 01 01 e8 90 00 } //1
		$a_01_3 = {49 6e 6a 65 63 74 4e 6f 72 6d 61 6c 52 6f 75 74 69 6e 65 00 49 6e 6a 65 63 74 65 64 53 68 65 6c 6c 43 6f 64 65 45 6e 64 } //1 湉敪瑣潎浲污潒瑵湩e湉敪瑣摥桓汥䍬摯䕥摮
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}