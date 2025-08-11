
rule Trojan_BAT_Purelogstealer_SEAW_MTB{
	meta:
		description = "Trojan:BAT/Purelogstealer.SEAW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 28 0a 00 00 06 0a 73 0b 00 00 0a 25 06 28 09 00 00 06 6f 0c 00 00 0a 0b } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}