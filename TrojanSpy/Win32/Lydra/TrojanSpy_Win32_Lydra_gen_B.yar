
rule TrojanSpy_Win32_Lydra_gen_B{
	meta:
		description = "TrojanSpy:Win32/Lydra.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,5a 00 50 00 06 00 00 32 00 "
		
	strings :
		$a_01_0 = {7b 36 35 44 35 41 46 46 42 2d 44 34 45 46 2d 34 39 41 41 2d 47 46 46 47 2d 35 44 41 35 45 31 32 45 33 30 30 41 7d } //0a 00  {65D5AFFB-D4EF-49AA-GFFG-5DA5E12E300A}
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4d 65 73 73 61 67 69 6e 67 20 53 75 62 73 79 73 74 65 6d } //0a 00  SOFTWARE\Microsoft\Windows Messaging Subsystem
		$a_00_2 = {4d 41 50 49 53 65 6e 64 4d 61 69 6c } //0a 00  MAPISendMail
		$a_00_3 = {52 6f 73 68 61 6c 2e 57 69 6e 52 41 52 2e 57 69 6e 52 41 52 } //0a 00  Roshal.WinRAR.WinRAR
		$a_01_4 = {55 6e 6d 61 70 56 69 65 77 4f 66 46 69 6c 65 } //0a 00  UnmapViewOfFile
		$a_00_5 = {73 6d 74 70 2e 6d 61 69 6c 2e 72 75 } //00 00  smtp.mail.ru
	condition:
		any of ($a_*)
 
}