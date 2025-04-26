
rule Trojan_BAT_CrimsonRat_A_MTB{
	meta:
		description = "Trojan:BAT/CrimsonRat.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 31 00 00 01 0a 02 02 7b 2d 00 00 04 06 16 1b 6f c7 00 00 0a 7d 35 00 00 04 06 16 28 c8 00 00 0a 0b 07 8d 31 00 00 01 0c 16 0d 07 13 04 2b 42 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}