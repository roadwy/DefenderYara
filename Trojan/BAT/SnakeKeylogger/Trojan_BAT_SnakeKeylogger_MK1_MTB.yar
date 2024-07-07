
rule Trojan_BAT_SnakeKeylogger_MK1_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.MK1!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_80_0 = {53 6e 61 6b 65 20 4b 65 79 6c 6f 67 67 65 72 } //Snake Keylogger  10
		$a_80_1 = {5c 53 6e 61 6b 65 4b 65 79 6c 6f 67 67 65 72 } //\SnakeKeylogger  10
		$a_80_2 = {5c 4c 6f 67 69 6e 20 44 61 74 61 } //\Login Data  10
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*10+(#a_80_2  & 1)*10) >=30
 
}