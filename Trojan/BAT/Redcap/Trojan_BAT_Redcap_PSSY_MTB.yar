
rule Trojan_BAT_Redcap_PSSY_MTB{
	meta:
		description = "Trojan:BAT/Redcap.PSSY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 72 6b 00 00 70 72 7b 00 00 70 28 07 00 00 06 02 72 6b 00 00 70 72 c7 00 00 70 28 07 00 00 06 02 7b 19 00 00 04 16 6f 2f 00 00 0a 02 7b 19 00 00 04 6f 30 00 00 0a 02 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}