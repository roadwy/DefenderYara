
rule Trojan_BAT_CoinMiner_AV_MSR{
	meta:
		description = "Trojan:BAT/CoinMiner.AV!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {51 6b 6b 62 61 6c } //01 00  Qkkbal
		$a_01_1 = {76 00 69 00 68 00 61 00 6e 00 73 00 6f 00 66 00 74 00 2e 00 69 00 72 00 } //01 00  vihansoft.ir
		$a_03_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6d 00 72 00 62 00 66 00 69 00 6c 00 65 00 2e 00 78 00 79 00 7a 00 2f 00 90 02 0f 2e 00 64 00 6c 00 6c 00 90 00 } //01 00 
		$a_01_3 = {2e 00 74 00 65 00 6d 00 70 00 } //00 00  .temp
	condition:
		any of ($a_*)
 
}