
rule Trojan_BAT_Taskun_ZGV_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ZGV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 02 09 11 04 6f ?? 00 00 06 13 05 04 03 6f ?? 00 00 0a 59 13 06 11 06 19 28 ?? 00 00 06 13 07 11 07 2c 0d 00 03 11 05 28 ?? 00 00 06 00 00 2b 18 11 06 16 fe 02 13 08 11 08 2c 0d 00 03 11 05 11 06 28 ?? 00 00 06 00 00 00 11 04 17 58 13 04 11 04 08 17 94 2f 0b 03 6f ?? 00 00 0a 04 fe 04 2b 01 16 13 09 11 09 2d 96 07 07 61 0b 00 09 17 58 0d 09 08 16 94 2f 0b 03 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}