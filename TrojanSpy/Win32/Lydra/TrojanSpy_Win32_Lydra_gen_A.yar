
rule TrojanSpy_Win32_Lydra_gen_A{
	meta:
		description = "TrojanSpy:Win32/Lydra.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,5a 00 50 00 07 00 00 32 00 "
		
	strings :
		$a_01_0 = {7b 00 32 00 41 00 44 00 46 00 35 00 2d 00 34 00 37 00 35 00 36 00 2d 00 34 00 34 00 38 00 31 00 2d 00 35 00 37 00 38 00 45 00 2d 00 37 00 38 00 37 00 35 00 34 00 35 00 38 00 38 00 35 00 38 00 39 00 30 00 30 00 7d 00 } //0a 00  {2ADF5-4756-4481-578E-7875458858900}
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4d 65 73 73 61 67 69 6e 67 20 53 75 62 73 79 73 74 65 6d } //0a 00  SOFTWARE\Microsoft\Windows Messaging Subsystem
		$a_00_2 = {4d 41 50 49 53 65 6e 64 4d 61 69 6c } //0a 00  MAPISendMail
		$a_00_3 = {52 6f 73 68 61 6c 2e 57 69 6e 52 41 52 2e 57 69 6e 52 41 52 } //0a 00  Roshal.WinRAR.WinRAR
		$a_01_4 = {55 6e 6d 61 70 56 69 65 77 4f 66 46 69 6c 65 } //0a 00  UnmapViewOfFile
		$a_00_5 = {73 6d 74 70 2e 6d 61 69 6c 2e 72 75 } //0a 00  smtp.mail.ru
		$a_00_6 = {69 66 20 65 78 69 73 74 20 25 31 20 67 6f 74 6f } //00 00  if exist %1 goto
	condition:
		any of ($a_*)
 
}