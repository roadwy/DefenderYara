
rule Trojan_BAT_Radthief_SIF_MTB{
	meta:
		description = "Trojan:BAT/Radthief.SIF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {1f 10 8d 1a 00 00 01 0b 1f 10 8d 1a 00 00 01 0c 7e 34 00 00 0a 0d 14 fe 06 1f 00 00 06 73 27 00 00 06 13 04 20 00 10 00 00 8d 1a 00 00 01 13 05 73 37 00 00 0a 13 06 7e 1d 00 00 04 16 08 16 1f 10 28 38 00 00 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}