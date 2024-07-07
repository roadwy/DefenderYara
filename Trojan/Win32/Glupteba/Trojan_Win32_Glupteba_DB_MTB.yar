
rule Trojan_Win32_Glupteba_DB_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 14 24 b8 d1 05 00 00 01 04 24 8b 04 24 8a 0c 30 8b 15 90 01 04 88 0c 32 81 c4 10 08 00 00 90 09 06 00 8b 15 90 00 } //1
		$a_03_1 = {89 04 24 b8 d1 05 00 00 01 04 24 8b 0c 24 8a 14 31 a1 90 01 04 88 14 30 81 c4 10 0c 00 00 90 09 05 00 a1 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}
rule Trojan_Win32_Glupteba_DB_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4c 24 4c 8b f0 83 64 24 90 01 02 d3 e6 03 74 24 90 01 01 81 6c 24 90 01 01 aa a0 5b 7e 81 44 24 90 01 01 62 7e e6 6f 81 44 24 90 01 01 4d 22 75 0e 8b 4c 24 90 01 01 8b d0 8b 5c 24 90 01 01 03 c3 d3 ea 03 54 24 90 01 01 33 d0 33 d6 2b fa 81 3d 90 01 04 fd 13 00 00 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Glupteba_DB_MTB_3{
	meta:
		description = "Trojan:Win32/Glupteba.DB!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f4 8a 44 02 ff 88 43 ff 3b 4d f4 77 df } //10
		$a_01_1 = {8b 55 a0 8b 45 9c 8b 00 89 02 8b 55 a0 8b 45 9c 8b 40 04 89 42 04 83 45 a0 08 83 45 9c 08 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}