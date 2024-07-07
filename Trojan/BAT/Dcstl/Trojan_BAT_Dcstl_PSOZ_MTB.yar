
rule Trojan_BAT_Dcstl_PSOZ_MTB{
	meta:
		description = "Trojan:BAT/Dcstl.PSOZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 73 1a 00 00 0a 0a 72 16 01 00 70 17 73 1b 00 00 0a 0b 06 07 28 90 01 03 0a 72 d7 01 00 70 28 90 01 03 0a 6f 90 01 03 0a 00 28 90 01 03 0a 72 d7 01 00 70 28 90 01 03 0a 28 1e 00 00 0a 26 2a 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}