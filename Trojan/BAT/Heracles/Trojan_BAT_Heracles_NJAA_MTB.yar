
rule Trojan_BAT_Heracles_NJAA_MTB{
	meta:
		description = "Trojan:BAT/Heracles.NJAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 0d 38 19 00 00 00 08 07 09 18 28 ?? 0e 00 06 1f 10 28 ?? 0e 00 06 28 ?? 0e 00 06 09 18 58 0d 09 07 28 ?? 0e 00 06 32 de } //4
		$a_01_1 = {51 00 79 00 6e 00 65 00 77 00 76 00 77 00 79 00 6d 00 63 00 2e 00 42 00 72 00 69 00 64 00 67 00 65 00 73 00 2e 00 53 00 65 00 72 00 76 00 65 00 72 00 } //1 Qynewvwymc.Bridges.Server
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}