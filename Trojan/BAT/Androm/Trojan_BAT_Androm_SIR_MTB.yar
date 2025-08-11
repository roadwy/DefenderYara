
rule Trojan_BAT_Androm_SIR_MTB{
	meta:
		description = "Trojan:BAT/Androm.SIR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 16 02 8e 69 6f 27 00 00 0a 6f 28 00 00 0a 6f 29 00 00 0a 7e 08 00 00 04 20 25 01 00 00 7e 08 00 00 04 20 25 01 00 00 94 7e 02 00 00 04 20 18 02 00 00 94 61 20 8c 00 00 00 5f 9e } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}