
rule Trojan_Linux_Pupy_B_MTB{
	meta:
		description = "Trojan:Linux/Pupy.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a 01 3c 09 0f 94 c2 3c 20 0f 94 c0 08 c2 75 ?? 48 89 e0 45 31 c9 c6 84 24 00 11 00 00 00 48 8d 14 38 29 d6 44 8d 04 0e 49 63 d0 48 8d 3c 10 } //1
		$a_00_1 = {88 8c 3c 90 21 00 00 48 ff c7 8a 0e 48 ff c6 80 f9 09 0f 95 c2 80 f9 20 0f 95 c0 84 d0 75 e1 41 8d 34 38 48 63 c7 c6 84 04 90 21 00 00 00 48 63 fe 48 8d 0c 3c eb 03 } //1
		$a_03_2 = {48 83 ca ff 48 89 c6 31 c0 fc 48 89 d1 48 89 f7 89 d5 f2 ae 48 f7 d1 48 01 d1 49 39 cf 0f 82 [0-05] 4c 89 f7 e8 [0-05] 4c 89 f7 e8 [0-05] 85 c0 89 c5 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}