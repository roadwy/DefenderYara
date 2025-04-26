
rule Adware_MacOS_Adload_AA_MTB{
	meta:
		description = "Adware:MacOS/Adload.AA!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {48 8b 00 48 89 45 d0 31 c0 48 89 47 10 48 89 47 08 48 89 bd 18 fe ff ff 48 89 07 48 89 85 00 ff ff ff 66 0f 57 c0 66 0f 29 85 f0 fe ff ff 48 89 85 30 ff ff ff 48 89 85 60 ff ff ff 88 85 70 ff ff ff 48 89 45 a8 48 89 45 a0 48 89 45 98 88 85 28 ff ff ff 48 89 85 20 ff ff ff 66 0f 29 85 10 ff ff ff 88 45 90 48 89 45 88 48 89 45 80 48 89 85 78 ff ff ff 88 45 c0 48 89 85 60 fe ff ff 66 0f 29 85 50 fe ff ff 48 8d 35 a7 e9 00 00 48 8d bd 30 bd ff ff ba 22 00 00 00 } //2
		$a_00_1 = {4c 8b ad d0 fe ff ff 4c 39 ad d8 fe ff ff 0f 84 84 09 00 00 48 8d 3d 59 b6 00 00 ba 07 00 00 00 4c 89 ee e8 bc ac 00 00 85 c0 0f 85 79 09 00 00 49 8d 75 10 49 63 45 08 49 8d 54 05 10 48 8d bd b0 fe ff ff e8 f1 51 00 00 48 8b 8d b0 fe ff ff 48 8b b5 b8 fe ff ff 48 39 ce 74 41 48 63 85 88 fe ff ff 48 69 d0 d3 4d 62 10 48 89 d6 48 c1 ee 3f 48 c1 ea 23 01 f2 6b d2 7d 29 d0 31 d2 30 04 11 } //2
		$a_01_2 = {75 75 69 64 5f 67 65 6e 65 72 61 74 65 5f 72 61 6e 64 6f 6d } //1 uuid_generate_random
		$a_01_3 = {6b 65 79 65 6e 75 6d 65 72 61 74 6f 72 } //1 keyenumerator
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}