
rule Trojan_BAT_Blubot_ABL_MTB{
	meta:
		description = "Trojan:BAT/Blubot.ABL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 0a 16 0b 2b 3a 03 07 6f ?? ?? ?? 0a 1f 61 32 0b 03 07 6f ?? ?? ?? 0a 1f 7a 31 1e 03 07 6f ?? ?? ?? 0a 1f 41 32 10 03 07 6f ?? ?? ?? 0a 1f 3e fe 02 16 fe 01 2b 04 16 2b 01 17 0a 07 17 58 0b 07 03 6f ?? ?? ?? 0a 2f 03 06 2c ba } //2
		$a_01_1 = {4d 00 43 00 42 00 4f 00 54 00 41 00 4c 00 50 00 48 00 41 00 } //1 MCBOTALPHA
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}