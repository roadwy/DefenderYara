
rule TrojanSpy_Win32_Bancos_gen_A{
	meta:
		description = "TrojanSpy:Win32/Bancos.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 3a 5c 49 6d 70 6f 72 74 61 6e 74 65 73 5c 69 65 20 69 63 6f 6e 65 73 5c 49 63 6f 6e 5f 39 2e 69 63 6f 00 } //01 00 
		$a_01_1 = {41 00 6e 00 74 00 69 00 56 00 69 00 72 00 75 00 73 00 2e 00 45 00 58 00 45 00 00 00 } //01 00 
		$a_01_2 = {42 61 6e 63 6f 20 53 61 66 72 61 20 53 2e 41 2e 00 } //01 00 
		$a_01_3 = {5c 4d 45 44 49 41 5c 57 69 6e 65 57 6f 72 6b 2e 65 78 65 00 } //01 00 
		$a_01_4 = {67 73 6d 74 70 31 38 35 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 00 } //01 00 
		$a_01_5 = {2d 73 65 6e 68 61 2d } //01 00  -senha-
		$a_01_6 = {43 61 69 78 61 } //00 00  Caixa
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_Win32_Bancos_gen_A_2{
	meta:
		description = "TrojanSpy:Win32/Bancos.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  \Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_1 = {42 6f 63 61 6c 20 4d 61 6c 20 58 20 4d 61 6c 20 4d 20 44 4f 49 44 4f } //01 00  Bocal Mal X Mal M DOIDO
		$a_01_2 = {53 65 6e 68 61 } //01 00  Senha
		$a_01_3 = {5b 42 42 5d 3d 2d 3d 2d } //01 00  [BB]=-=-
		$a_01_4 = {5b 73 70 63 5d 3d 2d 3d 2d 3d } //01 00  [spc]=-=-=
		$a_01_5 = {53 79 6d 61 6e 74 65 63 20 41 6e 74 69 20 56 69 72 75 73 } //01 00  Symantec Anti Virus
		$a_01_6 = {4e 6f 72 74 6f 6e 20 53 79 73 74 65 6d 57 6f 72 6b 73 } //01 00  Norton SystemWorks
		$a_01_7 = {be 01 00 00 00 8d 45 f4 8b 55 fc 8a 54 32 ff 80 ea 0a f6 d2 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_Win32_Bancos_gen_A_3{
	meta:
		description = "TrojanSpy:Win32/Bancos.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {5b 49 6e 66 65 63 74 61 64 6f 20 4f 6e 4c 69 6e 65 5d 3a 20 00 } //01 00 
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 4d 49 43 52 4f 53 4f 46 54 5c 4d 53 20 53 45 54 55 50 20 28 41 43 4d 45 29 5c 00 } //01 00  体呆䅗䕒䵜䍉佒体呆䵜⁓䕓啔⁐䄨䵃⥅\
		$a_01_2 = {5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 00 } //01 00 
		$a_01_3 = {67 73 6d 74 70 31 38 35 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 00 } //01 00 
		$a_01_4 = {42 61 6e 6b 42 6f 73 74 6f 6e 00 } //01 00 
		$a_01_5 = {42 61 6e 63 6f 44 4f 42 72 61 73 69 6c 00 } //01 00  慂据䑯䉏慲楳l
		$a_01_6 = {77 65 62 61 6e 6b 2f 53 65 72 76 69 63 6f 73 2f 4c 6f 67 69 6e 49 42 53 6f 43 6f 6e 73 75 6c 74 61 2e 61 73 70 00 } //01 00 
		$a_01_7 = {00 21 2f 2f 2d 2d 2d 2f 2f 2d 2d 2d 2f 2f 2d 2d 2d 2f 2f 2d 2d 2d 2f 2f 2d 2d 2d 2f 2f 00 } //00 00 
	condition:
		any of ($a_*)
 
}