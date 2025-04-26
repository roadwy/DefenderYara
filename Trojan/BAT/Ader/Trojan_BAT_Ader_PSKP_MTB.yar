
rule Trojan_BAT_Ader_PSKP_MTB{
	meta:
		description = "Trojan:BAT/Ader.PSKP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 59 00 00 70 28 08 00 00 06 0a 28 1a 00 00 0a 06 6f 1b 00 00 0a 28 1c 00 00 0a 28 01 00 00 2b 28 02 00 00 2b 0b de 03 26 de d4 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}