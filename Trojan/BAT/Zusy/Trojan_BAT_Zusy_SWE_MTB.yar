
rule Trojan_BAT_Zusy_SWE_MTB{
	meta:
		description = "Trojan:BAT/Zusy.SWE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 01 00 00 70 28 1e 00 00 0a 0b 07 28 03 00 00 2b 16 33 21 72 0f 00 00 70 28 20 00 00 0a 72 29 00 00 70 28 21 00 00 0a 28 22 00 00 0a 26 1f 64 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}