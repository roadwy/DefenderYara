
rule Trojan_BAT_Lokibot_DJ_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.DJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {4b 4f 4f 4f 4f 4f 4f 4f 4f 4f 4f 4f 4f 4f 4f 4f } //01 00  KOOOOOOOOOOOOOOO
		$a_81_1 = {52 41 54 43 72 79 70 74 5c 4c 4f 4b 49 5c } //01 00  RATCrypt\LOKI\
		$a_81_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_3 = {41 63 74 69 76 61 74 6f 72 } //01 00  Activator
		$a_81_4 = {52 65 70 6c 61 63 65 } //00 00  Replace
	condition:
		any of ($a_*)
 
}