
rule Trojan_BAT_Reline_DGB_MTB{
	meta:
		description = "Trojan:BAT/Reline.DGB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 11 00 00 "
		
	strings :
		$a_81_0 = {43 68 72 5f 30 5f 4d 5f 65 } //1 Chr_0_M_e
		$a_81_1 = {46 69 6c 65 5a 69 6c 6c 61 } //1 FileZilla
		$a_81_2 = {47 65 63 6b 6f } //1 Gecko
		$a_81_3 = {4e 6f 72 64 41 70 70 } //1 NordApp
		$a_81_4 = {53 74 72 69 6e 67 44 65 63 72 79 70 74 } //1 StringDecrypt
		$a_81_5 = {52 65 63 6f 75 72 73 69 76 65 46 69 6c 65 47 72 61 62 62 65 72 } //1 RecoursiveFileGrabber
		$a_81_6 = {41 6c 6c 57 61 6c 6c 65 74 73 52 75 6c 65 } //1 AllWalletsRule
		$a_81_7 = {41 72 6d 6f 72 79 52 75 6c 65 } //1 ArmoryRule
		$a_81_8 = {41 74 6f 6d 69 63 52 75 6c 65 } //1 AtomicRule
		$a_81_9 = {43 6f 69 6e 6f 6d 69 52 75 6c 65 } //1 CoinomiRule
		$a_81_10 = {44 65 73 6b 74 6f 70 4d 65 73 73 61 6e 67 65 72 52 75 6c 65 } //1 DesktopMessangerRule
		$a_81_11 = {44 69 73 63 6f 72 64 52 75 6c 65 } //1 DiscordRule
		$a_81_12 = {45 6c 65 63 74 72 75 6d 52 75 6c 65 } //1 ElectrumRule
		$a_81_13 = {45 74 68 52 75 6c 65 } //1 EthRule
		$a_81_14 = {45 5f 78 30 5f 64 5f 75 5f 53 } //1 E_x0_d_u_S
		$a_81_15 = {47 75 61 72 64 61 52 75 6c 65 } //1 GuardaRule
		$a_81_16 = {4f 70 65 6e 56 50 4e 52 75 6c 65 } //1 OpenVPNRule
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1+(#a_81_14  & 1)*1+(#a_81_15  & 1)*1+(#a_81_16  & 1)*1) >=17
 
}