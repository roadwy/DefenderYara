
rule Trojan_BAT_SnakeKeylogger_ABQN_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.ABQN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 61 00 00 70 28 90 01 03 06 0a 28 90 01 03 0a 06 6f 90 01 03 0a 28 90 01 03 0a 28 90 01 03 06 0b dd 90 01 03 00 26 dd 90 01 03 ff 07 2a 90 00 } //3
		$a_01_1 = {31 00 30 00 37 00 2e 00 31 00 37 00 32 00 2e 00 34 00 2e 00 31 00 36 00 39 00 2f 00 30 00 39 00 2f 00 44 00 61 00 74 00 69 00 79 00 63 00 76 00 6a 00 2e 00 62 00 6d 00 70 00 } //2 107.172.4.169/09/Datiycvj.bmp
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}