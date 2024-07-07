
rule Trojan_Win32_Amadey_MD_MTB{
	meta:
		description = "Trojan:Win32/Amadey.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 05 00 00 "
		
	strings :
		$a_01_0 = {40 5c cd cc f6 02 c2 02 db 7c 01 57 21 1c 8e 05 35 30 11 28 bb 3a 23 03 92 58 7b 6b a7 2b 7a 41 } //5
		$a_01_1 = {9e 76 e9 3c 64 10 14 76 2a 3b 0f 5c f9 43 b4 61 6a 7c 2f 77 33 61 55 49 58 06 65 20 86 7d 17 02 a2 50 e8 18 9f 39 04 33 08 4a 3c 7d ec 07 e8 02 } //5
		$a_01_2 = {e0 00 02 01 0b 01 0e 18 00 bc 02 00 00 d6 00 00 00 00 00 00 3d 52 89 00 00 10 } //5
		$a_01_3 = {2e 76 6d 70 30 } //2 .vmp0
		$a_01_4 = {2e 76 6d 70 31 } //2 .vmp1
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=19
 
}