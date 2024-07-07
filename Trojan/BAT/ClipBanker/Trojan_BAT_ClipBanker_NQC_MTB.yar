
rule Trojan_BAT_ClipBanker_NQC_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.NQC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 17 7d 07 00 00 04 72 90 01 02 00 70 18 73 90 01 02 00 0a 0a 02 06 28 90 01 02 00 0a 00 2a 90 00 } //5
		$a_01_1 = {43 72 79 70 74 6f 4c 61 75 6e 63 68 65 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 CryptoLauncher.Properties.Resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}