
rule Trojan_BAT_Lokibot_PSOL_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.PSOL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {60 7e 01 00 00 04 02 25 17 58 10 00 91 1f 18 62 60 0c 28 1e 00 00 0a 7e 01 00 00 04 02 08 6f 1f 00 00 0a 28 20 00 00 0a a5 02 00 00 1b 0b 11 07 20 a6 d7 df e7 5a 20 fa cc 6e f4 61 38 5e fd ff ff } //00 00 
	condition:
		any of ($a_*)
 
}