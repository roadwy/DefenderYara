
rule Trojan_BAT_Rozena_SPRA_MTB{
	meta:
		description = "Trojan:BAT/Rozena.SPRA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 1d 59 0d 07 11 0a 91 13 0b 11 0b 11 05 61 13 0c 11 04 09 58 13 04 07 11 0a 11 0c d2 9c 00 11 0a 17 58 13 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}