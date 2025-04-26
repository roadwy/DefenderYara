
rule Trojan_BAT_CryptInject_MBXT_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.MBXT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {46 53 43 56 4c 41 42 41 51 47 48 55 47 57 55 00 41 42 56 50 53 4c 48 4e 4a } //3
		$a_01_1 = {74 43 54 36 42 30 77 36 61 00 63 48 38 49 58 63 77 } //2
		$a_01_2 = {42 6f 74 43 6c 69 65 6e 74 } //1 BotClient
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=6
 
}