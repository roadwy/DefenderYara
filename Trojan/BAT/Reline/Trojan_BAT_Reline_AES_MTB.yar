
rule Trojan_BAT_Reline_AES_MTB{
	meta:
		description = "Trojan:BAT/Reline.AES!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 11 00 00 01 00 "
		
	strings :
		$a_81_0 = {43 5f 68 5f 72 5f 6f 5f 6d 5f 65 } //01 00  C_h_r_o_m_e
		$a_81_1 = {46 69 6c 65 5a 69 6c 6c 61 } //01 00  FileZilla
		$a_81_2 = {47 65 63 6b 6f } //01 00  Gecko
		$a_81_3 = {4e 6f 72 64 41 70 70 } //01 00  NordApp
		$a_81_4 = {52 65 63 6f 75 72 73 69 76 65 46 69 6c 65 47 72 61 62 62 65 72 } //01 00  RecoursiveFileGrabber
		$a_81_5 = {41 6c 6c 57 61 6c 6c 65 74 73 52 75 6c 65 } //01 00  AllWalletsRule
		$a_81_6 = {41 72 6d 6f 72 79 52 75 6c 65 } //01 00  ArmoryRule
		$a_81_7 = {41 74 6f 6d 69 63 52 75 6c 65 } //01 00  AtomicRule
		$a_81_8 = {43 6f 69 6e 6f 6d 69 52 75 6c 65 } //01 00  CoinomiRule
		$a_81_9 = {44 69 73 63 6f 72 64 52 75 6c 65 } //01 00  DiscordRule
		$a_81_10 = {45 6c 65 63 74 72 75 6d 52 75 6c 65 } //01 00  ElectrumRule
		$a_81_11 = {45 74 68 52 75 6c 65 } //01 00  EthRule
		$a_81_12 = {45 78 6f 64 75 73 52 75 6c 65 } //01 00  ExodusRule
		$a_81_13 = {47 61 6d 65 4c 61 75 6e 63 68 65 72 52 75 6c 65 } //01 00  GameLauncherRule
		$a_81_14 = {47 75 61 72 64 61 52 75 6c 65 } //01 00  GuardaRule
		$a_81_15 = {4f 70 65 6e 56 50 4e 52 75 6c 65 } //01 00  OpenVPNRule
		$a_81_16 = {50 72 6f 74 6f 6e 56 50 4e 52 75 6c 65 } //00 00  ProtonVPNRule
	condition:
		any of ($a_*)
 
}