
rule Trojan_BAT_SnakeKeylogger_EJKC_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.EJKC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {58 07 8e 69 5d 13 0e 07 11 0e 11 0b 9c 11 0e 17 58 07 8e 69 5d } //1
		$a_02_1 = {08 07 8e 69 5d 13 11 07 11 11 11 0f 11 10 91 9c 03 11 0f 11 10 91 ?? ?? ?? ?? ?? 08 17 58 07 8e 69 5d 0c 11 10 17 58 13 10 11 10 11 0d 32 d1 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}