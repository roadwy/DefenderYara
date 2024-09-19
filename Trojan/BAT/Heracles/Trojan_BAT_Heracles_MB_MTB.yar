
rule Trojan_BAT_Heracles_MB_MTB{
	meta:
		description = "Trojan:BAT/Heracles.MB!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 0e 05 00 06 28 0c 05 00 06 72 b1 00 00 70 06 28 a7 02 00 06 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}