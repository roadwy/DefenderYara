
rule Trojan_BAT_BPLogger_ALBB_MTB{
	meta:
		description = "Trojan:BAT/BPLogger.ALBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 11 05 11 09 6f ?? 00 00 0a 13 0a 72 60 07 00 70 12 0a 28 ?? 00 00 0a 8c ?? 00 00 01 12 0a 28 ?? 00 00 0a 8c ?? 00 00 01 12 0a 28 ?? 00 00 0a 8c ?? 00 00 01 28 ?? 00 00 0a 13 0b 11 0b 6f ?? 00 00 0a 1c fe 01 13 0c } //5
		$a_03_1 = {01 25 16 11 05 20 ff 00 00 00 5d 8c ?? 00 00 01 a2 25 17 11 05 18 5a 20 ff 00 00 00 5d 8c ?? 00 00 01 a2 25 18 11 05 19 5a 20 ff 00 00 00 5d 8c ?? 00 00 01 a2 25 19 11 05 1a 5a 20 ff 00 00 00 5d } //2
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*2) >=7
 
}