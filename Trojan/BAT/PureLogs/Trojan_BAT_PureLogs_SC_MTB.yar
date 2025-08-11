
rule Trojan_BAT_PureLogs_SC_MTB{
	meta:
		description = "Trojan:BAT/PureLogs.SC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {7e 01 00 00 04 6f 05 00 00 0a 0a 38 0c 00 00 00 12 00 28 06 00 00 0a 6f 0c 00 00 06 12 00 28 07 00 00 0a 2d eb dd 0e 00 00 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}