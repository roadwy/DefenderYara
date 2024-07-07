
rule Trojan_BAT_Reline_BF_MTB{
	meta:
		description = "Trojan:BAT/Reline.BF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 10 00 00 "
		
	strings :
		$a_81_0 = {43 68 72 5f 30 5f 4d 5f 65 } //1 Chr_0_M_e
		$a_81_1 = {46 69 6c 65 5a 69 6c 6c 61 } //1 FileZilla
		$a_81_2 = {67 5f 45 5f 63 5f } //1 g_E_c_
		$a_81_3 = {43 72 79 70 74 6f 48 65 6c 70 65 72 } //1 CryptoHelper
		$a_81_4 = {41 6c 6c 57 61 6c 6c 65 74 73 } //1 AllWallets
		$a_81_5 = {4f 70 65 6e 56 50 4e } //1 OpenVPN
		$a_81_6 = {57 61 6c 6c 65 74 43 6f 6e 66 69 67 } //1 WalletConfig
		$a_81_7 = {53 63 61 6e 6e 65 64 43 6f 6f 6b 69 65 } //1 ScannedCookie
		$a_81_8 = {42 43 52 59 50 54 5f 41 55 54 48 45 4e 54 49 43 41 54 45 44 5f 43 49 50 48 45 52 5f 4d 4f 44 45 5f 49 4e 46 4f } //1 BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO
		$a_81_9 = {54 72 79 49 6e 69 74 43 6f 6c 64 57 61 6c 6c 65 74 73 } //1 TryInitColdWallets
		$a_81_10 = {54 72 79 49 6e 69 74 44 69 73 63 6f 72 64 } //1 TryInitDiscord
		$a_81_11 = {54 72 79 49 6e 69 74 4e 6f 72 64 56 50 4e } //1 TryInitNordVPN
		$a_81_12 = {67 65 74 5f 53 63 61 6e 47 65 63 6b 6f 42 72 6f 77 73 65 72 73 50 61 74 68 73 } //1 get_ScanGeckoBrowsersPaths
		$a_81_13 = {67 65 74 5f 46 74 70 43 6f 6e 6e 65 63 74 69 6f 6e 73 } //1 get_FtpConnections
		$a_81_14 = {61 73 64 6b 39 33 34 35 61 73 64 } //1 asdk9345asd
		$a_81_15 = {6b 6b 64 68 66 61 6b 64 61 73 64 } //1 kkdhfakdasd
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1+(#a_81_14  & 1)*1+(#a_81_15  & 1)*1) >=16
 
}