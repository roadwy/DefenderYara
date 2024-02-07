
rule TrojanDropper_Win32_Bancos_A{
	meta:
		description = "TrojanDropper:Win32/Bancos.A,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8b 55 d8 8d 45 dc b9 00 00 00 00 e8 90 01 02 fa ff 8b 45 dc e8 90 01 02 fa ff 50 e8 90 01 02 fa ff 8d 45 d4 50 8b cb ba 90 01 04 8b c6 90 00 } //01 00 
		$a_00_1 = {44 00 41 00 44 00 4f 00 53 00 45 00 43 00 4f 00 4e 00 44 00 3d 00 4f 00 4b 00 } //01 00  DADOSECOND=OK
		$a_00_2 = {5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //00 00  \Software\Microsoft\Windows\CurrentVersion\Run
	condition:
		any of ($a_*)
 
}