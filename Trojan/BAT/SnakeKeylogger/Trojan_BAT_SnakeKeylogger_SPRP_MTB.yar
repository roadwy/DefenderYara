
rule Trojan_BAT_SnakeKeylogger_SPRP_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPRP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {02 7b 09 00 00 04 08 03 58 09 04 58 28 ?? ?? ?? 0a 1f 23 fe 01 13 05 11 05 2c 04 06 17 58 0a } //4
		$a_01_1 = {47 41 64 6d 69 6e 4c 69 62 2e 52 65 73 6f 75 72 63 65 44 41 } //1 GAdminLib.ResourceDA
		$a_01_2 = {47 54 41 5f 50 41 53 53 57 4f 52 44 } //1 GTA_PASSWORD
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=6
 
}