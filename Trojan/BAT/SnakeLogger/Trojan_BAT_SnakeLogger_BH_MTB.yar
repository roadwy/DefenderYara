
rule Trojan_BAT_SnakeLogger_BH_MTB{
	meta:
		description = "Trojan:BAT/SnakeLogger.BH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {17 13 0c 09 11 0a 07 11 0a 91 11 04 11 0b 95 61 d2 9c 00 11 0a 17 58 13 0a 11 0a 07 8e 69 fe 04 } //3
		$a_01_1 = {95 58 20 ff 00 00 00 5f } //1
		$a_01_2 = {34 00 49 00 38 00 37 00 48 00 48 00 43 00 48 00 42 00 4a 00 38 00 49 00 54 00 37 00 31 00 34 00 50 00 34 00 38 00 52 00 52 00 34 00 } //1 4I87HHCHBJ8IT714P48RR4
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}