
rule Trojan_BAT_PureLogs_SP_MTB{
	meta:
		description = "Trojan:BAT/PureLogs.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 05 09 11 04 11 05 08 11 05 59 6f 12 00 00 0a 58 13 05 11 05 08 32 e8 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}