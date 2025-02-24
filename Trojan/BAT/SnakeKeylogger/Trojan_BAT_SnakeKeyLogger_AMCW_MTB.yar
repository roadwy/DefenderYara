
rule Trojan_BAT_SnakeKeyLogger_AMCW_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.AMCW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 00 6e 00 61 00 6b 00 65 00 20 00 4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 20 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 0d 00 0a 00 46 00 6f 00 75 00 6e 00 64 } //3
		$a_80_1 = {4d 6f 7a 69 6c 6c 61 5c 46 69 72 65 66 6f 78 5c 50 72 6f 66 69 6c 65 73 } //Mozilla\Firefox\Profiles  1
		$a_80_2 = {6c 6f 67 69 6e 73 2e 6a 73 6f 6e } //logins.json  1
	condition:
		((#a_01_0  & 1)*3+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=5
 
}