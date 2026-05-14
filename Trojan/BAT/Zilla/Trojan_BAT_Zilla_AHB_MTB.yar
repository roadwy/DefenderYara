
rule Trojan_BAT_Zilla_AHB_MTB{
	meta:
		description = "Trojan:BAT/Zilla.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 08 9a 0d 00 09 6f ?? ?? ?? 0a 18 33 08 09 6f ?? ?? ?? 0a 2b 01 16 13 04 11 04 2c 06 00 17 13 05 2b 10 00 08 17 58 0c 08 07 8e 69 32 d2 } //30
		$a_03_1 = {08 09 9a 13 04 00 11 04 6f ?? ?? ?? 0a 18 fe 01 13 05 11 05 2c 0b 00 11 04 6f ?? ?? ?? 0a 0a 2b 0b 00 09 17 58 0d 09 08 8e 69 32 d4 } //20
	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*20) >=50
 
}