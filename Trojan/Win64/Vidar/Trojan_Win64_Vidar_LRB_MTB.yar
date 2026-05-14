
rule Trojan_Win64_Vidar_LRB_MTB{
	meta:
		description = "Trojan:Win64/Vidar.LRB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 03 00 00 "
		
	strings :
		$a_01_0 = {89 44 24 20 6b 44 24 20 07 89 44 24 24 8b 44 24 20 83 c0 2a 89 44 24 28 8b 44 24 24 8b 4c 24 28 33 c1 89 44 24 2c 8b 44 24 2c 89 44 24 30 48 83 c4 48 } //20
		$a_01_1 = {48 63 44 24 04 48 8b 4c 24 10 0f be 04 01 85 c0 74 19 6b 04 24 1f 48 63 4c 24 04 48 8b 54 24 10 0f b6 0c 0a 03 c1 89 04 24 } //10
		$a_81_2 = {43 3a 5c 74 67 62 6f 74 73 69 64 65 6c 6f 61 64 69 6e 67 5c 73 69 64 65 6c 6f 61 64 5c 78 36 34 5c 41 64 } //5 C:\tgbotsideloading\sideload\x64\Ad
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10+(#a_81_2  & 1)*5) >=35
 
}