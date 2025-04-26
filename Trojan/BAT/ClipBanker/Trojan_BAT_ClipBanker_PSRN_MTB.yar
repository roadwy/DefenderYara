
rule Trojan_BAT_ClipBanker_PSRN_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.PSRN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 09 00 00 06 0a 28 08 00 00 0a 06 6f 09 00 00 0a 28 08 00 00 06 75 01 00 00 1b 0b 07 16 07 8e 69 28 0a 00 00 0a 07 2a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}