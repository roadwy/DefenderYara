
rule Trojan_BAT_PureLogStealer_ZQT_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.ZQT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 03 00 00 "
		
	strings :
		$a_03_0 = {02 12 07 28 ?? 00 00 0a 12 07 28 ?? 00 00 0a 6f ?? 00 00 0a 13 17 73 ?? 00 00 0a 13 18 11 18 72 8f 02 00 70 09 6f ?? 00 00 0a 23 00 00 00 00 00 80 76 40 5a } //6
		$a_03_1 = {08 11 18 6f ?? 00 00 0a 00 11 05 72 db 02 00 70 12 17 28 ?? 00 00 0a 12 17 28 ?? 00 00 0a 58 12 17 28 ?? 00 00 0a 58 6b 22 00 00 40 40 5b 22 00 00 7f 43 5b } //5
		$a_03_2 = {59 13 19 12 07 28 ?? 00 00 0a 1f 14 5d 2d 0c 11 04 6f ?? 00 00 0a 16 fe 02 2b 01 16 } //4
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*5+(#a_03_2  & 1)*4) >=15
 
}