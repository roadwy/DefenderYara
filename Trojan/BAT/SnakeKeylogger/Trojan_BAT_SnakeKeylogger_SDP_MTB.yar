
rule Trojan_BAT_SnakeKeylogger_SDP_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 11 06 18 6f ?? 00 00 0a 13 07 08 11 06 18 5b 11 07 1f 10 28 ?? 00 00 0a 9c 00 11 06 18 58 13 06 11 06 07 6f ?? 00 00 0a fe 04 13 08 11 08 2d ce } //1
		$a_01_1 = {51 00 75 00 61 00 6e 00 4c 00 79 00 51 00 75 00 61 00 6e 00 54 00 53 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 QuanLyQuanTS.Properties.Resources
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}