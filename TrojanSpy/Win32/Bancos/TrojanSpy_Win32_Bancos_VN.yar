
rule TrojanSpy_Win32_Bancos_VN{
	meta:
		description = "TrojanSpy:Win32/Bancos.VN,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {31 43 6c 69 63 6b 13 00 90 02 08 49 6d 61 67 65 90 10 03 00 43 6c 69 63 6b 90 00 } //01 00 
		$a_00_1 = {4d 65 6e 73 61 67 65 6d 20 64 61 20 70 e1 67 69 6e 61 20 64 61 20 77 65 62 00 00 00 49 6e 73 74 61 6c 61 e7 e3 6f 20 65 6d 20 61 6e 64 61 6d 65 6e 74 6f 2e } //01 00 
		$a_00_2 = {5c 57 69 6e 64 6f 77 73 5c 53 43 52 2e 6a 70 67 } //00 00  \Windows\SCR.jpg
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_Win32_Bancos_VN_2{
	meta:
		description = "TrojanSpy:Win32/Bancos.VN,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 00 2a 00 5c 00 41 00 44 00 3a 00 5c 00 74 00 75 00 64 00 6f 00 5c 00 62 00 61 00 69 00 78 00 61 00 20 00 64 00 61 00 72 00 6c 00 61 00 6d 00 5c 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 31 00 2e 00 76 00 62 00 70 00 } //01 00  C*\AD:\tudo\baixa darlam\Project1.vbp
		$a_01_1 = {53 00 63 00 72 00 69 00 70 00 74 00 69 00 6e 00 67 00 2e 00 46 00 69 00 6c 00 65 00 53 00 79 00 73 00 74 00 65 00 6d 00 4f 00 62 00 6a 00 65 00 63 00 74 00 } //01 00  Scripting.FileSystemObject
		$a_01_2 = {4d 00 41 00 49 00 4c 00 20 00 46 00 52 00 4f 00 4d 00 3a 00 20 00 3c 00 } //00 00  MAIL FROM: <
	condition:
		any of ($a_*)
 
}