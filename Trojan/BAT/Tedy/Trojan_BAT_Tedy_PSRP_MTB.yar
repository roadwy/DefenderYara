
rule Trojan_BAT_Tedy_PSRP_MTB{
	meta:
		description = "Trojan:BAT/Tedy.PSRP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 72 01 00 00 70 72 f6 00 00 70 28 05 00 00 06 28 13 00 00 0a 72 22 01 00 70 28 04 00 00 06 00 16 28 14 00 00 0a 00 2a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}