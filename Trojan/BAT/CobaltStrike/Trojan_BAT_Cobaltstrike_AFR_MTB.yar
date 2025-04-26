
rule Trojan_BAT_Cobaltstrike_AFR_MTB{
	meta:
		description = "Trojan:BAT/Cobaltstrike.AFR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 fe 01 0a 06 2c 0e 00 72 e3 00 00 70 28 26 00 00 0a 0b 2b 0d 72 fd 00 00 70 28 26 00 00 0a 0b } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}