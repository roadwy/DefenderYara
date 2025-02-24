
rule Trojan_BAT_Cerbu_AMCQ_MTB{
	meta:
		description = "Trojan:BAT/Cerbu.AMCQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 06 17 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 73 ?? 00 00 0a 25 06 03 04 6f ?? 00 00 0a 17 73 ?? 00 00 0a 25 02 16 02 8e 69 6f ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 0b de 09 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}