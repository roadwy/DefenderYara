
rule Trojan_BAT_Xmrig_NEAF_MTB{
	meta:
		description = "Trojan:BAT/Xmrig.NEAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_01_0 = {6f 54 00 00 0a 14 19 8d 01 00 00 01 0a 06 16 02 a2 06 17 03 a2 06 18 04 a2 06 6f 55 00 00 0a 26 de 03 } //10
		$a_01_1 = {78 00 4b 00 55 00 69 00 67 00 41 00 4d 00 71 00 50 00 71 00 4d 00 50 00 76 00 44 00 39 00 46 00 75 00 30 00 54 00 62 00 45 00 41 00 3d 00 3d 00 } //2 xKUigAMqPqMPvD9Fu0TbEA==
		$a_01_2 = {75 00 63 00 35 00 54 00 31 00 76 00 68 00 6c 00 4c 00 55 00 57 00 33 00 42 00 6c 00 31 00 30 00 36 00 77 00 4f 00 4a 00 6a 00 51 00 3d 00 3d 00 } //2 uc5T1vhlLUW3Bl106wOJjQ==
		$a_01_3 = {5a 57 4d 32 4d 7a 4a 6d 5a 44 6b 74 4d 54 59 35 4e 43 30 30 5a 6a 52 68 4c 54 6c 69 5a 6d 59 74 5a 6a 49 77 4e 6a 41 77 5a 54 4d 33 4f 54 67 78 } //2 ZWM2MzJmZDktMTY5NC00ZjRhLTliZmYtZjIwNjAwZTM3OTgx
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=16
 
}