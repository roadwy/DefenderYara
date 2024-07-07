
rule Trojan_BAT_Nanocore_PSQW_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.PSQW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {6f d2 00 00 0a 6f d3 00 00 0a 28 21 02 00 06 38 1e 00 00 00 00 11 03 11 02 16 11 07 6f d4 00 00 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}