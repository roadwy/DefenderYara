
rule Trojan_BAT_SnakeKeylogger_ABUX_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.ABUX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 0d 2b 29 00 07 09 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 13 05 08 17 8d ?? 00 00 01 25 16 11 05 9c 6f ?? 00 00 0a 00 09 18 58 0d 00 09 07 6f ?? 00 00 0a fe 04 13 06 11 06 2d c8 } //4
		$a_01_1 = {71 00 75 00 61 00 6e 00 6c 00 79 00 63 00 75 00 61 00 68 00 61 00 6e 00 67 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 quanlycuahang.Properties.Resources
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}