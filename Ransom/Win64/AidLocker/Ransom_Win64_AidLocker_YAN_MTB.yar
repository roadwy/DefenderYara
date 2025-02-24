
rule Ransom_Win64_AidLocker_YAN_MTB{
	meta:
		description = "Ransom:Win64/AidLocker.YAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {48 65 6c 6c 6f 2c 20 41 69 64 4c 6f 63 6b 65 72 20 69 73 20 68 65 72 65 } //10 Hello, AidLocker is here
		$a_01_1 = {64 6f 77 6e 6c 6f 61 64 65 64 20 79 6f 75 72 20 64 61 74 61 } //1 downloaded your data
		$a_01_2 = {65 6e 63 72 79 70 74 65 64 20 79 6f 75 72 20 66 69 6c 65 73 } //1 encrypted your files
		$a_01_3 = {64 65 6c 65 74 65 64 20 62 61 63 6b 75 70 73 } //1 deleted backups
		$a_01_4 = {72 65 73 74 6f 72 65 20 79 6f 75 72 20 69 6e 66 72 61 73 74 72 75 63 74 75 72 65 } //1 restore your infrastructure
		$a_01_5 = {70 75 62 6c 69 63 61 74 69 6f 6e 20 6f 66 20 79 6f 75 72 20 64 61 74 61 } //1 publication of your data
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}