
rule Ransom_Win32_Sfiles_B_dha{
	meta:
		description = "Ransom:Win32/Sfiles.B!dha,SIGNATURE_TYPE_PEHSTR,04 00 04 00 07 00 00 "
		
	strings :
		$a_01_0 = {2d 3e 43 6f 6e 66 69 64 65 6e 74 69 61 6c 20 66 69 6c 65 73 2c 20 50 61 73 73 70 6f 72 74 73 2c 20 48 52 20 64 69 72 65 63 74 6f 72 69 65 73 2c 20 45 6d 70 6c 6f 79 65 65 73 20 70 65 72 73 6f 6e 61 6c 20 69 6e 66 6f } //1 ->Confidential files, Passports, HR directories, Employees personal info
		$a_01_1 = {2d 3e 44 65 74 61 69 6c 65 64 20 63 6f 6d 70 61 6e 79 20 69 6e 66 6f 72 6d 61 74 69 6f 6e 2c 20 41 63 63 6f 75 6e 74 61 6e 74 20 66 69 6c 65 73 } //1 ->Detailed company information, Accountant files
		$a_01_2 = {2d 3e 46 69 6e 61 6e 63 69 61 6c 20 64 6f 63 75 6d 65 6e 74 73 2c 20 43 6f 6d 6d 65 72 63 69 61 6c 20 69 6e 66 6f } //1 ->Financial documents, Commercial info
		$a_01_3 = {25 77 73 20 45 6e 63 72 79 70 74 69 6f 6e 53 74 61 67 65 31 20 62 65 67 69 6e } //1 %ws EncryptionStage1 begin
		$a_01_4 = {25 77 73 20 45 6e 63 72 79 70 74 69 6f 6e 53 74 61 67 65 32 20 62 65 67 69 6e 2c 20 74 6f 74 61 6c 6c 79 20 25 64 20 66 69 6c 65 73 20 69 6e 20 71 75 65 75 65 } //1 %ws EncryptionStage2 begin, totally %d files in queue
		$a_01_5 = {57 61 69 74 46 6f 72 48 6f 75 72 73 28 29 20 3a 20 67 6f 67 6f 67 6f } //1 WaitForHours() : gogogo
		$a_01_6 = {21 00 20 00 63 00 79 00 6e 00 65 00 74 00 20 00 72 00 61 00 6e 00 73 00 6f 00 6d 00 20 00 70 00 72 00 6f 00 74 00 65 00 63 00 74 00 69 00 6f 00 6e 00 28 00 64 00 6f 00 6e 00 27 00 74 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 29 00 } //1 ! cynet ransom protection(don't delete)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=4
 
}