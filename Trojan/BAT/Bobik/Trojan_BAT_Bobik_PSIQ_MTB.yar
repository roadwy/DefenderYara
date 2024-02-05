
rule Trojan_BAT_Bobik_PSIQ_MTB{
	meta:
		description = "Trojan:BAT/Bobik.PSIQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {d0 2b 00 00 02 7e 51 01 00 04 28 86 03 00 06 7e 5c 01 00 04 28 b2 03 00 06 72 8c 04 00 70 7e 7a 01 00 04 28 ea 03 00 06 73 2a 00 00 0a 25 7e 61 01 00 04 28 c2 03 00 06 16 6a 7e 62 01 00 04 28 c6 03 00 06 25 25 7e 61 01 00 04 28 c2 03 00 06 7e 76 01 00 04 28 de 03 00 06 69 7e 7b 01 00 04 28 ee 03 00 06 0a 7e 39 01 00 04 28 32 03 00 06 06 28 a4 00 00 06 2a } //00 00 
	condition:
		any of ($a_*)
 
}