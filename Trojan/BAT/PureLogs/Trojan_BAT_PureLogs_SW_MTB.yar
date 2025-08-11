
rule Trojan_BAT_PureLogs_SW_MTB{
	meta:
		description = "Trojan:BAT/PureLogs.SW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {38 0c 00 00 00 12 00 28 06 00 00 0a 6f 0a 00 00 06 12 00 28 07 00 00 0a 2d eb dd 0e 00 00 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}