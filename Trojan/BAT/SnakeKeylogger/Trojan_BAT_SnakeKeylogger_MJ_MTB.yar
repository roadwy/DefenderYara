
rule Trojan_BAT_SnakeKeylogger_MJ_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.MJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 03 00 00 "
		
	strings :
		$a_01_0 = {11 04 6f 0c 00 00 0a 13 05 11 05 72 e6 2a 0e 70 72 f8 2a 0e 70 28 01 00 00 06 13 06 18 8d 0b 00 00 01 13 07 11 07 16 72 32 2b 0e 70 a2 11 07 17 11 06 28 01 00 00 0a a2 11 07 13 08 } //10
		$a_01_1 = {47 00 6f 00 74 00 69 00 63 00 32 00 2e 00 47 00 6f 00 74 00 69 00 63 00 32 00 } //2 Gotic2.Gotic2
		$a_01_2 = {54 00 54 00 52 00 44 00 5a 00 42 00 57 00 49 00 69 00 6d 00 6a 00 4a 00 5a 00 72 00 47 00 } //2 TTRDZBWIimjJZrG
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=14
 
}