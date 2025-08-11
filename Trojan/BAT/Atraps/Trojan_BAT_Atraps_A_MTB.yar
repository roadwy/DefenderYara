
rule Trojan_BAT_Atraps_A_MTB{
	meta:
		description = "Trojan:BAT/Atraps.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 02 7b 06 00 00 04 28 53 00 00 06 10 01 73 62 00 00 0a 13 05 73 63 00 00 0a 0b 73 63 00 00 0a 0c 72 d4 11 00 70 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}