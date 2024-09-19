
rule Trojan_BAT_Lokibot_RGAA_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.RGAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {11 07 11 0f d4 11 13 20 ff 00 00 00 5f d2 9c } //2
		$a_01_1 = {11 06 11 11 20 ff 00 00 00 5f 95 d2 13 12 11 10 11 12 61 13 13 } //3
		$a_01_2 = {35 00 32 00 34 00 4f 00 5a 00 34 00 43 00 54 00 51 00 37 00 5a 00 4a 00 38 00 47 00 45 00 37 00 49 00 37 00 43 00 38 00 4a 00 41 00 } //1 524OZ4CTQ7ZJ8GE7I7C8JA
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1) >=6
 
}