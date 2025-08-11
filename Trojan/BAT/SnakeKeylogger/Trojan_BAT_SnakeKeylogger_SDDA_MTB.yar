
rule Trojan_BAT_SnakeKeylogger_SDDA_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SDDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 06 8e 69 5d 91 61 d2 9c 00 08 17 58 0c 08 7e 04 00 00 04 8e 69 fe 04 0d 09 2d d9 } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}
rule Trojan_BAT_SnakeKeylogger_SDDA_MTB_2{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SDDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {04 19 8d 89 00 00 01 25 16 0f 01 28 ?? 00 00 0a 9c 25 17 0f 01 28 ?? 00 00 0a 9c 25 18 0f 01 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 11 08 } //2
		$a_03_1 = {07 12 03 28 ?? 00 00 0a 12 03 28 ?? 00 00 0a 58 12 03 28 ?? 00 00 0a 58 58 0b 02 09 04 05 28 ?? 00 00 06 11 0a } //1
		$a_01_2 = {53 74 6f 72 65 50 69 78 65 6c 44 61 74 61 } //1 StorePixelData
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}