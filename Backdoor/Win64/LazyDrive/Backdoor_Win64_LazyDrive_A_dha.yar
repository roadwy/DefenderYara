
rule Backdoor_Win64_LazyDrive_A_dha{
	meta:
		description = "Backdoor:Win64/LazyDrive.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {6e 6f 72 6d 61 6c 2d 73 6c 65 65 70 79 } //1 normal-sleepy
		$a_01_1 = {73 65 6d 69 2d 73 6c 65 65 70 79 } //1 semi-sleepy
		$a_01_2 = {53 6c 65 65 70 79 20 73 74 61 74 75 73 } //1 Sleepy status
		$a_01_3 = {45 72 72 6f 72 20 69 6e 20 67 65 74 74 69 6e 67 20 76 61 6c 75 65 20 66 72 6f 6d 20 6a 73 6f 6e 20 66 69 6c 65 20 2c 20 6d 61 79 62 65 20 43 67 72 69 64 20 69 73 20 69 6e 76 61 6c 69 64 } //2 Error in getting value from json file , maybe Cgrid is invalid
		$a_01_4 = {2f 76 31 2e 30 2f 6d 65 2f 64 72 69 76 65 2f 72 6f 6f 74 3a 2f 65 6d 70 6c 6f 79 65 65 2f 46 6f 6c 64 65 72 5f 4e 61 6d 65 2f } //2 /v1.0/me/drive/root:/employee/Folder_Name/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=3
 
}