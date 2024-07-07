
rule Ransom_Win32_IncRansom_YAA_MTB{
	meta:
		description = "Ransom:Win32/IncRansom.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {57 00 61 00 6c 00 6c 00 70 00 61 00 70 00 65 00 72 00 } //1 Wallpaper
		$a_01_1 = {49 00 4e 00 43 00 2d 00 52 00 45 00 41 00 44 00 4d 00 45 00 } //1 INC-README
		$a_01_2 = {62 00 61 00 63 00 6b 00 67 00 72 00 6f 00 75 00 6e 00 64 00 2d 00 69 00 6d 00 61 00 67 00 65 00 2e 00 6a 00 70 00 67 00 } //1 background-image.jpg
		$a_01_3 = {53 57 35 6a 4c 69 42 53 59 57 35 7a 62 32 31 33 59 58 4a 6c 44 51 6f 4e 43 6c 64 6c 49 47 68 68 64 6d 55 67 61 47 46 6a 61 32 56 6b 49 48 6c 76 64 53 42 68 62 6d 51 67 } //1 SW5jLiBSYW5zb213YXJlDQoNCldlIGhhdmUgaGFja2VkIHlvdSBhbmQg
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}