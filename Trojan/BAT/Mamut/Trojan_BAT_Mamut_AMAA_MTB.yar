
rule Trojan_BAT_Mamut_AMAA_MTB{
	meta:
		description = "Trojan:BAT/Mamut.AMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 13 04 73 ?? 00 00 0a 0b 02 28 ?? 00 00 06 75 ?? 00 00 1b 73 ?? 00 00 0a 0c 08 11 04 16 73 ?? 00 00 0a 0d 09 07 6f ?? 00 00 0a 07 13 05 de 15 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}