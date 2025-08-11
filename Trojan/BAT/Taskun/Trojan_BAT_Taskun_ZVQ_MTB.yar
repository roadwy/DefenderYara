
rule Trojan_BAT_Taskun_ZVQ_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ZVQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 06 07 6f ?? 00 00 0a 0d 04 03 6f ?? 00 00 0a 59 13 04 72 0d 07 00 70 0e 05 8c ?? 00 00 01 28 ?? 00 00 0a 13 05 11 05 72 ?? 07 00 70 6f ?? 00 00 0a 13 0a 11 0a 2c 07 } //6
		$a_03_1 = {08 1f 63 58 0c 00 03 12 03 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 04 17 59 25 13 04 16 fe 02 16 fe 01 13 0b 11 0b 2c 02 } //5
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*5) >=11
 
}