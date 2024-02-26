
rule Trojan_BAT_AsyncRAT_ABBK_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.ABBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {70 13 05 28 90 01 03 0a 6f 90 01 03 0a 6f 90 01 03 0a 13 06 72 90 01 03 70 28 90 01 03 06 28 90 01 03 0a 00 00 de 0d 11 04 2c 08 11 04 6f 90 01 03 0a 00 dc 90 00 } //01 00 
		$a_01_1 = {41 00 73 00 79 00 6e 00 63 00 43 00 43 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //01 00  AsyncCC.Properties.Resources
		$a_01_2 = {4d 00 75 00 6c 00 74 00 69 00 63 00 68 00 61 00 69 00 6e 00 5f 00 4e 00 46 00 54 00 5f 00 53 00 6e 00 69 00 70 00 65 00 72 00 5f 00 42 00 6f 00 74 00 } //00 00  Multichain_NFT_Sniper_Bot
	condition:
		any of ($a_*)
 
}