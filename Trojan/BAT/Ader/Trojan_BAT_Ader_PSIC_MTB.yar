
rule Trojan_BAT_Ader_PSIC_MTB{
	meta:
		description = "Trojan:BAT/Ader.PSIC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 03 07 18 6f 16 00 00 0a 1f 10 28 17 00 00 0a 6f 18 00 00 0a 07 18 58 0b 07 03 6f 19 00 00 0a 32 de 06 6f 1a 00 00 0a 2a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}