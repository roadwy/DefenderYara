
rule Trojan_Win64_Redcap_NR_MTB{
	meta:
		description = "Trojan:Win64/Redcap.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b 3d 78 5e 0a 00 44 8b 0f 45 85 c9 0f 85 ac 02 00 00 65 48 8b 04 25 90 01 04 48 8b 1d ac 5d 0a 00 48 8b 70 08 31 ed 90 00 } //3
		$a_03_1 = {75 e2 48 8b 35 90 01 04 31 ed 8b 06 83 f8 90 01 01 0f 84 13 02 00 00 8b 06 90 00 } //3
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}
rule Trojan_Win64_Redcap_NR_MTB_2{
	meta:
		description = "Trojan:Win64/Redcap.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {3a 5c 6d 61 6c 77 61 72 65 5c 42 6c 61 63 6b 2d 41 6e 67 65 6c 2d 52 6f 6f 74 6b 69 74 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 42 6c 61 63 6b 20 41 6e 67 65 6c 20 43 6c 69 65 6e 74 2e 70 64 62 } //1 :\malware\Black-Angel-Rootkit\x64\Release\Black Angel Client.pdb
		$a_01_1 = {48 69 64 65 20 50 72 6f 63 65 73 73 } //1 Hide Process
		$a_01_2 = {45 6c 65 76 61 74 65 20 50 72 6f 63 65 73 73 } //1 Elevate Process
		$a_01_3 = {50 72 6f 74 65 63 74 20 50 72 6f 63 65 73 73 } //1 Protect Process
		$a_01_4 = {48 69 64 65 20 44 69 72 65 63 74 6f 72 79 } //1 Hide Directory
		$a_01_5 = {48 69 64 65 20 50 6f 72 74 } //1 Hide Port
		$a_01_6 = {48 69 64 65 20 52 65 67 69 73 74 72 79 20 4b 65 79 } //1 Hide Registry Key
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}