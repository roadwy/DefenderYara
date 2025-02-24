
rule Trojan_BAT_Jalapeno_MX_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.MX!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 1a 8d 3a 00 00 01 25 16 72 71 00 00 70 a2 25 17 72 c9 00 00 70 a2 25 18 72 1b 01 00 70 a2 25 19 72 73 01 00 70 a2 7d 08 00 00 04 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}