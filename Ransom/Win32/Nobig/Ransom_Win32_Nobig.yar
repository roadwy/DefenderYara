
rule Ransom_Win32_Nobig{
	meta:
		description = "Ransom:Win32/Nobig,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 07 00 00 "
		
	strings :
		$a_01_0 = {54 6f 20 72 65 73 74 6f 72 65 20 74 68 65 20 66 69 6c 65 73 2c 20 77 72 6f 74 65 20 74 6f 20 74 68 65 20 65 6d 61 69 6c 3a 62 6f 6d 62 6f 6d 73 31 32 33 40 6d 61 69 6c 2e 72 75 } //5 To restore the files, wrote to the email:bomboms123@mail.ru
		$a_01_1 = {69 66 20 79 6f 75 20 64 6f 20 6e 6f 74 20 72 65 63 65 69 76 65 20 61 20 72 65 73 70 6f 6e 73 65 20 66 72 6f 6d 20 74 68 69 73 20 6d 61 69 6c 20 77 69 74 68 69 6e 20 32 34 20 68 6f 75 72 73 20 74 68 65 6e 20 77 72 69 74 65 20 74 6f 20 20 74 68 65 20 73 75 62 73 69 64 69 61 72 79 3a 79 6f 75 72 66 6f 6f 64 32 30 40 6d 61 69 6c 2e 72 75 } //5 if you do not receive a response from this mail within 24 hours then write to  the subsidiary:yourfood20@mail.ru
		$a_01_2 = {65 00 63 00 68 00 6f 00 20 00 64 00 65 00 6c 00 20 00 65 00 6c 00 65 00 76 00 61 00 74 00 6f 00 72 00 2e 00 65 00 78 00 65 00 20 00 3e 00 3e 00 20 00 64 00 6c 00 73 00 2e 00 62 00 61 00 74 00 } //5 echo del elevator.exe >> dls.bat
		$a_01_3 = {35 2e 38 2e 38 38 2e 32 33 37 } //5 5.8.88.237
		$a_01_4 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 47 49 42 4f 4e } //5 User-Agent: GIBON
		$a_01_5 = {46 49 4e 44 20 47 49 42 4f 4e 20 42 55 46 46 45 52 20 53 49 5a 45 } //5 FIND GIBON BUFFER SIZE
		$a_01_6 = {46 49 4e 44 20 47 49 42 4f 4e 20 53 55 50 45 52 41 44 4d 49 4e 20 4d 45 53 53 41 47 45 } //5 FIND GIBON SUPERADMIN MESSAGE
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5+(#a_01_5  & 1)*5+(#a_01_6  & 1)*5) >=15
 
}