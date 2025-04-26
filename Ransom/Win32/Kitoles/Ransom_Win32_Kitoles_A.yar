
rule Ransom_Win32_Kitoles_A{
	meta:
		description = "Ransom:Win32/Kitoles.A,SIGNATURE_TYPE_PEHSTR,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {5b 2f 45 58 54 45 4e 53 49 4f 4e 5d 5b 54 41 52 47 45 54 53 5d } //2 [/EXTENSION][TARGETS]
		$a_01_1 = {5b 42 41 43 4b 55 50 53 5d 5b 44 52 49 56 45 53 5d 5b 53 48 41 52 45 53 5d } //2 [BACKUPS][DRIVES][SHARES]
		$a_01_2 = {5b 2f 54 41 53 4b 4e 41 4d 45 5d 5b 41 55 54 4f 45 58 45 43 5d 5b 52 45 41 44 4d 45 5d } //2 [/TASKNAME][AUTOEXEC][README]
		$a_01_3 = {59 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 6e 6f 77 20 65 6e 63 72 79 70 74 65 64 21 } //1 Your files are now encrypted!
		$a_01_4 = {63 72 79 70 74 6f 6c 6f 63 6b 65 72 } //1 cryptolocker
		$a_01_5 = {62 69 74 63 6f 69 6e } //1 bitcoin
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}
rule Ransom_Win32_Kitoles_A_2{
	meta:
		description = "Ransom:Win32/Kitoles.A,SIGNATURE_TYPE_PEHSTR,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {59 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 21 } //2 Your files are encrypted!
		$a_01_1 = {54 6f 20 64 65 63 72 79 70 74 20 66 69 6c 65 73 2c 20 70 6c 65 61 73 65 20 63 6f 6e 74 61 63 74 20 75 73 20 62 79 20 65 6d 61 69 6c 3a } //2 To decrypt files, please contact us by email:
		$a_01_2 = {64 65 63 72 79 70 74 73 40 61 69 72 6d 61 69 6c 2e 63 63 } //2 decrypts@airmail.cc
		$a_01_3 = {48 4f 57 20 54 4f 20 52 45 43 4f 56 45 52 20 45 4e 43 52 59 50 54 45 44 20 46 49 4c 45 53 20 2d 20 64 65 63 72 79 70 74 73 40 61 69 72 6d 61 69 6c 2e 63 63 2e 54 58 54 } //2 HOW TO RECOVER ENCRYPTED FILES - decrypts@airmail.cc.TXT
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}