
rule Trojan_BAT_Reline_V_MTB{
	meta:
		description = "Trojan:BAT/Reline.V!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 01 00 "
		
	strings :
		$a_81_0 = {41 6c 6c 57 61 6c 6c 65 74 73 52 75 6c 65 } //01 00  AllWalletsRule
		$a_81_1 = {43 6f 69 6e 6f 6d 69 52 75 6c 65 } //01 00  CoinomiRule
		$a_81_2 = {4a 61 78 78 52 75 6c 65 } //01 00  JaxxRule
		$a_81_3 = {41 72 6d 6f 72 79 52 75 6c 65 } //01 00  ArmoryRule
		$a_81_4 = {50 72 6f 74 6f 6e 56 50 4e 52 75 6c 65 } //01 00  ProtonVPNRule
		$a_81_5 = {45 78 6f 64 75 73 52 75 6c 65 } //01 00  ExodusRule
		$a_81_6 = {45 6c 65 63 74 72 75 6d 52 75 6c 65 } //01 00  ElectrumRule
		$a_81_7 = {47 75 61 72 64 61 52 75 6c 65 } //01 00  GuardaRule
		$a_81_8 = {41 74 6f 6d 69 63 52 75 6c 65 } //01 00  AtomicRule
		$a_81_9 = {53 63 61 6e 6e 65 64 42 72 6f 77 73 65 72 } //01 00  ScannedBrowser
		$a_81_10 = {53 63 61 6e 6e 65 64 43 6f 6f 6b 69 65 } //00 00  ScannedCookie
	condition:
		any of ($a_*)
 
}