
rule Backdoor_BAT_Androm_AGQA_MTB{
	meta:
		description = "Backdoor:BAT/Androm.AGQA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 17 9a 6f ?? 00 00 0a 1e 09 5a 59 13 04 11 04 16 fe 04 13 05 11 05 2c 0a 00 1e 11 04 58 0c 16 13 04 00 7e ?? 00 00 04 07 09 59 06 17 9a 11 04 08 6f ?? 00 00 0a 18 28 ?? 00 00 0a 9c 00 09 17 58 0d 09 07 fe 02 16 fe 01 13 06 11 06 2d b0 } //5
		$a_03_1 = {0f 00 08 20 00 04 00 00 58 28 ?? 00 00 2b 00 07 02 08 20 00 04 00 00 6f ?? 00 00 0a 0d 08 09 58 0c 09 20 00 04 00 00 fe 04 13 04 11 04 2c 0c 00 0f 00 08 28 ?? 00 00 2b 00 2b 06 00 17 13 05 2b be } //2
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*2) >=7
 
}