
rule Trojan_BAT_Nanocore_PSWE_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.PSWE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 ad 02 00 70 11 04 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 00 1f 7b 28 90 01 01 00 00 0a 00 28 04 00 00 06 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 72 ad 02 00 70 11 04 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 26 1f 7b 28 90 01 01 00 00 0a 00 de 0e 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}