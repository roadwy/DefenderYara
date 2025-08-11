
rule Trojan_BAT_PureLogs_BAA_MTB{
	meta:
		description = "Trojan:BAT/PureLogs.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 73 14 00 00 0a 13 04 38 00 00 00 00 00 11 04 11 03 16 73 1b 00 00 0a 13 05 38 00 00 00 00 00 73 0b 00 00 0a 13 06 38 00 00 00 00 00 11 05 11 06 ?? ?? 00 00 0a 38 00 00 00 00 11 06 ?? ?? 00 00 0a 13 07 38 00 00 00 00 dd 55 ff ff ff 11 06 39 11 00 00 00 38 00 00 00 00 11 06 ?? ?? 00 00 0a 38 00 00 00 00 dc } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}