
rule Trojan_BAT_Zusy_PSTZ_MTB{
	meta:
		description = "Trojan:BAT/Zusy.PSTZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {73 12 00 00 0a 25 72 01 00 00 70 72 49 00 00 70 6f 90 01 01 00 00 0a 72 65 00 00 70 72 ab 00 00 70 6f 90 01 01 00 00 0a 72 ab 00 00 70 28 90 01 01 00 00 0a 26 2a 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}