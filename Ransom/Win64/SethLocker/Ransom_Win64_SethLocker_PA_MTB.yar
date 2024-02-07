
rule Ransom_Win64_SethLocker_PA_MTB{
	meta:
		description = "Ransom:Win64/SethLocker.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 73 65 74 68 } //01 00  .seth
		$a_01_1 = {25 55 53 45 52 50 52 4f 46 49 4c 45 25 5c 44 65 73 6b 74 6f 70 5c 48 4f 57 5f 44 45 43 52 59 50 54 5f 46 49 4c 45 53 2e 73 65 74 68 2e 74 78 74 } //01 00  %USERPROFILE%\Desktop\HOW_DECRYPT_FILES.seth.txt
		$a_01_2 = {25 61 70 70 64 61 74 61 25 5c 63 6f 64 65 62 69 6e 64 2e 62 61 74 } //01 00  %appdata%\codebind.bat
		$a_01_3 = {54 69 74 6c 65 20 53 65 74 68 20 4c 6f 63 6b 65 72 } //01 00  Title Seth Locker
		$a_01_4 = {4f 6f 70 73 2c 20 59 6f 75 72 20 46 69 6c 65 73 20 48 61 76 65 20 42 65 65 6e 20 45 6e 63 72 79 70 74 65 64 21 } //00 00  Oops, Your Files Have Been Encrypted!
	condition:
		any of ($a_*)
 
}