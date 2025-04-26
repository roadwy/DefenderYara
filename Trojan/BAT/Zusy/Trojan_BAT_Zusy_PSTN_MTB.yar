
rule Trojan_BAT_Zusy_PSTN_MTB{
	meta:
		description = "Trojan:BAT/Zusy.PSTN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 11 00 00 70 72 06 01 00 70 73 11 00 00 0a 72 14 01 00 70 28 13 00 00 0a 72 52 01 00 70 28 14 00 00 0a 28 01 00 00 06 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}