
rule Trojan_BAT_Zusy_PTAU_MTB{
	meta:
		description = "Trojan:BAT/Zusy.PTAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 59 00 00 70 a2 28 14 00 00 0a 18 28 01 00 00 2b 28 16 00 00 0a 0a 06 1f 0a 8d 23 00 00 01 25 16 7e 12 00 00 0a 6f 13 00 00 0a a2 25 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}