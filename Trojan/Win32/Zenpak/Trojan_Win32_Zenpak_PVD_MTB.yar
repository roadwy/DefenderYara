
rule Trojan_Win32_Zenpak_PVD_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.PVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_02_0 = {8d 34 07 e8 90 01 04 30 06 83 6c 24 08 01 8b 44 24 08 85 c0 7d 90 00 } //2
		$a_00_1 = {8b 45 80 33 85 7c ff ff ff 89 45 80 8b 4d 84 8b 55 90 8b 45 80 89 04 8a e9 } //2
		$a_02_2 = {8b c7 c1 e9 05 03 4d 90 01 01 c1 e0 04 03 45 90 01 01 33 c8 8d 04 3b 2b 5d 90 01 01 33 c8 2b f1 83 6d fc 01 75 90 00 } //2
		$a_02_3 = {34 39 88 81 90 01 01 a9 41 00 41 83 f9 08 72 90 09 07 00 8a 04 4d 90 01 01 a9 41 00 90 00 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_00_1  & 1)*2+(#a_02_2  & 1)*2+(#a_02_3  & 1)*2) >=2
 
}