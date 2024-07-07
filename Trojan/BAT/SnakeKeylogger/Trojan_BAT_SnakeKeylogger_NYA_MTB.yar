
rule Trojan_BAT_SnakeKeylogger_NYA_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.NYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {57 3f b6 1f 09 1f 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 1c 01 00 00 81 00 00 00 79 01 00 00 25 03 00 00 e7 02 00 00 17 00 00 00 ad 02 } //1
		$a_01_1 = {10 00 00 00 af 00 00 00 1c 00 00 00 b8 00 00 00 01 00 00 00 01 00 00 00 06 00 00 00 0b 00 00 00 0f 00 00 00 37 00 00 00 0a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}