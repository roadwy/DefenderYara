
rule Trojan_BAT_Seraph_AMAE_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AMAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 1c d2 13 31 11 1c 1e 63 d1 13 1c 11 17 11 09 91 13 2c 11 17 11 09 11 ?? 11 ?? 61 11 1d 19 58 61 11 31 61 d2 9c ?? ?? ?? 58 13 09 11 2c 13 1d 11 09 11 25 32 a4 } //5
		$a_01_1 = {11 2e 11 14 11 0e 11 14 91 9d 11 14 17 58 13 14 11 14 11 1b 32 ea } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}