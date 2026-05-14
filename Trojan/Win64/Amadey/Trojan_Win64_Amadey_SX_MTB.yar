
rule Trojan_Win64_Amadey_SX_MTB{
	meta:
		description = "Trojan:Win64/Amadey.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 06 00 00 "
		
	strings :
		$a_01_0 = {0f 11 4d b8 0f 11 4d c8 0f 11 4d d8 0f 11 4d e8 0f 11 4d f8 0f 11 4d 08 33 c0 0f 11 45 90 48 89 45 a0 c7 45 88 01 00 00 00 4c 89 7d 80 45 33 c9 4c 8d 44 24 78 48 8d 54 24 68 48 8d 4c 24 60 ff 15 } //10
		$a_01_1 = {c7 44 24 40 20 00 cc 00 44 89 6c 24 38 44 89 6c 24 30 4c 89 7c 24 28 8b 8d b0 00 00 00 89 4c 24 20 44 8b 8d b4 00 00 00 45 33 c0 33 d2 48 8b cf } //5
		$a_01_2 = {6e 65 74 20 6c 6f 63 61 6c 67 72 6f 75 70 20 22 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 73 } //1 net localgroup "Administrators
		$a_01_3 = {53 45 54 20 50 61 73 73 77 6f 72 64 63 68 61 6e 67 65 61 62 6c 65 3d 46 41 4c 53 45 } //1 SET Passwordchangeable=FALSE
		$a_01_4 = {57 4d 49 43 20 55 53 45 52 41 43 43 4f 55 4e 54 20 57 48 45 52 45 20 22 4e 61 6d 65 20 3d 20 27 } //1 WMIC USERACCOUNT WHERE "Name = '
		$a_01_5 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 43 6f 6d 6d 61 6e 64 20 45 78 70 61 6e 64 2d 41 72 63 68 69 76 65 20 2d 50 61 74 68 20 27 } //1 powershell -Command Expand-Archive -Path '
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=19
 
}