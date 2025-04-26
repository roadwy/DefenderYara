
rule Trojan_BAT_SnakeKeylogger_SPY_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {07 09 06 09 9a 1f 10 28 44 00 00 0a 9c 00 09 17 58 0d 09 06 8e 69 fe 04 13 04 11 04 2d e1 } //3
		$a_01_1 = {56 69 74 61 6d 69 6e 41 70 65 72 31 30 30 } //1 VitaminAper100
		$a_01_2 = {73 71 75 65 65 7a 61 62 6c 65 46 72 75 69 74 5f 62 74 6e } //1 squeezableFruit_btn
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}