
rule Trojan_BAT_Barys_PSUL_MTB{
	meta:
		description = "Trojan:BAT/Barys.PSUL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 36 00 00 01 13 04 7e 43 00 00 04 02 1a 58 11 04 16 08 28 ?? 00 00 0a 28 ?? 00 00 0a 11 04 16 11 04 8e 69 6f ?? 00 00 0a 13 05 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}