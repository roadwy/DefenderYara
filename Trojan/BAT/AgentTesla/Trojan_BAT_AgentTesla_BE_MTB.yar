
rule Trojan_BAT_AgentTesla_BE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {57 15 a2 09 09 09 00 00 00 5a a4 01 00 14 00 00 01 00 00 00 34 00 00 00 } //1
		$a_01_1 = {32 00 2e 00 35 00 36 00 2e 00 35 00 37 00 2e 00 31 00 32 00 34 00 2f 00 74 00 69 00 6d 00 6f 00 5f 00 4e 00 6e 00 78 00 64 00 64 00 72 00 73 00 66 00 2e 00 70 00 6e 00 67 00 } //1 2.56.57.124/timo_Nnxddrsf.png
		$a_01_2 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
		$a_01_3 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule Trojan_BAT_AgentTesla_BE_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.BE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0e 00 00 "
		
	strings :
		$a_81_0 = {43 68 72 5f 30 5f 4d 5f 65 } //1 Chr_0_M_e
		$a_81_1 = {46 69 6c 65 5a 69 6c 6c 61 } //1 FileZilla
		$a_81_2 = {67 5f 45 5f 63 5f } //1 g_E_c_
		$a_81_3 = {4e 6f 72 64 41 70 70 } //1 NordApp
		$a_81_4 = {43 72 79 70 74 6f 48 65 6c 70 65 72 } //1 CryptoHelper
		$a_81_5 = {46 69 6c 65 53 63 61 6e 6e 69 6e 67 } //1 FileScanning
		$a_81_6 = {41 6c 6c 57 61 6c 6c 65 74 73 } //1 AllWallets
		$a_81_7 = {41 74 6f 6d 69 63 } //1 Atomic
		$a_81_8 = {42 69 6e 61 6e 63 65 } //1 Binance
		$a_81_9 = {43 5f 6f 31 5f 6e 30 5f 6d } //1 C_o1_n0_m
		$a_81_10 = {45 4c 33 5f 4b 5f 54 72 30 30 4d } //1 EL3_K_Tr00M
		$a_81_11 = {45 5f 78 30 5f 64 5f 75 5f 53 } //1 E_x0_d_u_S
		$a_81_12 = {50 72 6f 74 6f 6e 56 50 4e } //1 ProtonVPN
		$a_81_13 = {42 43 52 59 50 54 5f 41 55 54 48 45 4e 54 49 43 41 54 45 44 5f 43 49 50 48 45 52 5f 4d 4f 44 45 5f 49 4e 46 4f } //1 BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1) >=14
 
}
rule Trojan_BAT_AgentTesla_BE_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.BE!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 69 74 74 73 62 75 72 67 68 31 32 4d 6f 64 65 } //1 Pittsburgh12Mode
		$a_01_1 = {74 78 74 53 74 6f 72 65 5f 4b 65 79 44 6f 77 6e } //1 txtStore_KeyDown
		$a_01_2 = {4e 6f 53 70 61 63 65 43 6f 70 79 54 65 78 74 42 6f 78 } //1 NoSpaceCopyTextBox
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}