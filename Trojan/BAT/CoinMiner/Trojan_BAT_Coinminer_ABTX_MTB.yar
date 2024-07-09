
rule Trojan_BAT_Coinminer_ABTX_MTB{
	meta:
		description = "Trojan:BAT/Coinminer.ABTX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 0e 20 e8 03 00 00 28 ?? ?? ?? 0a 06 17 58 0a 06 7e 06 00 00 04 28 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}