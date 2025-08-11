
rule Trojan_BAT_PureLogs_BAB_MTB{
	meta:
		description = "Trojan:BAT/PureLogs.BAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 73 07 00 00 0a 13 04 38 00 00 00 00 00 11 04 11 03 16 73 08 00 00 0a 13 05 38 00 00 00 00 00 73 09 00 00 0a 13 06 38 00 00 00 00 00 11 05 11 06 ?? ?? 00 00 0a 38 00 00 00 00 11 06 ?? ?? 00 00 0a 13 07 38 00 00 00 00 dd 82 00 00 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}