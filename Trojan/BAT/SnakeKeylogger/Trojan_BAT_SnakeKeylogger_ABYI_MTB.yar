
rule Trojan_BAT_SnakeKeylogger_ABYI_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.ABYI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 02 16 02 8e 69 6f ?? 00 00 0a 0a 2b 00 06 2a 90 0a 19 00 7e ?? 00 00 04 6f } //2
		$a_01_1 = {53 00 70 00 61 00 63 00 65 00 54 00 65 00 61 00 6d 00 } //1 SpaceTeam
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}