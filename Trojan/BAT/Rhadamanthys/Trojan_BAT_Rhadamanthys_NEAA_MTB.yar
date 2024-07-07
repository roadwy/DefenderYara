
rule Trojan_BAT_Rhadamanthys_NEAA_MTB{
	meta:
		description = "Trojan:BAT/Rhadamanthys.NEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 00 06 13 00 38 00 00 00 00 28 02 00 00 0a 11 00 6f 03 00 00 0a 28 04 00 00 0a 28 05 00 00 06 13 01 38 00 00 00 00 dd 10 00 00 00 26 38 00 00 00 00 dd 90 01 04 38 00 00 00 00 11 01 2a 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}