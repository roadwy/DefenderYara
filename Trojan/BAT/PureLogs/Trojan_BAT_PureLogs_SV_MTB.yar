
rule Trojan_BAT_PureLogs_SV_MTB{
	meta:
		description = "Trojan:BAT/PureLogs.SV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 05 00 00 0a 72 01 00 00 70 73 06 00 00 0a 28 07 00 00 0a 6f 08 00 00 0a 0a 06 39 0a 00 00 00 06 16 06 8e 69 28 09 00 00 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}