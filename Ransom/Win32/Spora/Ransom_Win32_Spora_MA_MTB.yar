
rule Ransom_Win32_Spora_MA_MTB{
	meta:
		description = "Ransom:Win32/Spora.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {41 00 6c 00 6c 00 20 00 59 00 6f 00 75 00 72 00 20 00 46 00 69 00 6c 00 65 00 73 00 20 00 45 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 20 00 54 00 6f 00 20 00 44 00 65 00 63 00 72 00 79 00 70 00 74 00 69 00 6f 00 6e 00 20 00 45 00 6d 00 61 00 69 00 6c 00 20 00 55 00 73 00 } //1 All Your Files Encrypted To Decryption Email Us
		$a_01_1 = {76 00 73 00 73 00 61 00 64 00 6d 00 69 00 6e 00 2e 00 65 00 78 00 65 00 20 00 44 00 65 00 6c 00 65 00 74 00 65 00 20 00 53 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 41 00 6c 00 6c 00 20 00 2f 00 51 00 75 00 69 00 65 00 74 00 } //1 vssadmin.exe Delete Shadows /All /Quiet
		$a_01_2 = {73 63 68 74 61 73 6b 73 20 2f 64 65 6c 65 74 65 20 2f 74 6e 20 4d 69 63 72 6f 73 6f 66 74 5f 41 75 74 6f 5f 53 63 68 65 64 75 6c 65 72 } //1 schtasks /delete /tn Microsoft_Auto_Scheduler
		$a_81_3 = {5c 52 65 73 74 6f 72 65 5f 59 6f 75 72 5f 46 69 6c 65 73 2e 74 78 74 } //1 \Restore_Your_Files.txt
		$a_01_4 = {5f 45 6e 63 72 79 70 74 69 6f 6e 5f 4d 6f 64 65 3a } //1 _Encryption_Mode:
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_81_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}