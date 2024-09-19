
rule Trojan_BAT_MassLogger_RDB_MTB{
	meta:
		description = "Trojan:BAT/MassLogger.RDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 04 06 16 06 8e 69 6f 1c 00 00 0a 09 6f 1d 00 00 0a 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}