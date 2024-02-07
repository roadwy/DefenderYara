
rule Backdoor_BAT_AsyncRAT_ABH_MTB{
	meta:
		description = "Backdoor:BAT/AsyncRAT.ABH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 07 00 00 03 00 "
		
	strings :
		$a_01_0 = {57 9f a2 3f 09 02 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 77 00 00 00 14 00 00 00 3d 00 00 00 8c 00 00 00 73 00 00 00 } //01 00 
		$a_01_1 = {47 65 74 54 65 6d 70 46 69 6c 65 4e 61 6d 65 } //01 00  GetTempFileName
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_3 = {55 70 6c 6f 61 64 56 61 6c 75 65 73 } //01 00  UploadValues
		$a_01_4 = {67 65 74 5f 45 78 65 63 75 74 61 62 6c 65 50 61 74 68 } //01 00  get_ExecutablePath
		$a_01_5 = {47 65 74 54 65 6d 70 50 61 74 68 } //01 00  GetTempPath
		$a_01_6 = {63 00 20 00 73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 20 00 2f 00 64 00 65 00 6c 00 65 00 74 00 65 00 } //00 00  c schtasks /delete
	condition:
		any of ($a_*)
 
}