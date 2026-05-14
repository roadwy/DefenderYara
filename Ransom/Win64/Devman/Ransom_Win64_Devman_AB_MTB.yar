
rule Ransom_Win64_Devman_AB_MTB{
	meta:
		description = "Ransom:Win64/Devman.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {59 4f 55 52 20 46 49 4c 45 53 20 48 41 56 45 20 42 45 45 4e 20 45 4e 43 52 59 50 54 45 44 } //1 YOUR FILES HAVE BEEN ENCRYPTED
		$a_81_1 = {44 45 56 4d 41 4e 20 33 2e 30 } //1 DEVMAN 3.0
		$a_81_2 = {31 2e 20 46 69 6e 64 20 21 21 21 5f 52 45 41 44 5f 4d 45 5f 21 21 21 2e 74 78 74 20 6f 6e 20 79 6f 75 72 20 64 65 73 6b 74 6f 70 } //1 1. Find !!!_READ_ME_!!!.txt on your desktop
		$a_81_3 = {73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 73 20 24 70 63 20 2f 75 20 24 75 20 2f 70 20 24 70 20 2f 74 6e 20 24 74 6e 20 2f 74 72 20 22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 24 6e 61 6d 65 22 20 2f 73 63 20 6f 6e 63 65 20 2f 73 74 20 30 30 3a 30 30 20 2f 72 75 20 53 59 53 54 45 4d 20 2f 66 20 32 3e 24 6e 75 6c 6c } //1 schtasks /create /s $pc /u $u /p $p /tn $tn /tr "C:\ProgramData\$name" /sc once /st 00:00 /ru SYSTEM /f 2>$null
		$a_81_4 = {61 6e 64 20 62 61 63 6b 75 70 73 20 68 61 76 65 20 62 65 65 6e 20 6c 6f 63 6b 65 64 } //1 and backups have been locked
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}