
rule Trojan_BAT_Androm_MBGM_MTB{
	meta:
		description = "Trojan:BAT/Androm.MBGM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b 2c 11 07 07 09 58 08 11 04 58 6f ?? 00 00 0a 13 0a 12 0a 28 ?? 00 00 0a 13 08 11 06 11 05 11 08 9c 11 05 17 58 13 05 11 04 17 58 13 04 11 04 17 32 cf } //1
		$a_03_1 = {16 13 05 20 01 ae 00 00 8d ?? 00 00 01 13 06 06 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}