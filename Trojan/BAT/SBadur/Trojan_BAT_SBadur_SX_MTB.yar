
rule Trojan_BAT_SBadur_SX_MTB{
	meta:
		description = "Trojan:BAT/SBadur.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {70 11 06 8c 2d 00 00 01 28 ?? 00 00 0a 28 ?? 00 00 0a 00 20 e8 03 00 00 28 ?? 00 00 0a 00 00 11 06 17 59 13 06 } //20
		$a_03_1 = {2c 02 2b 6c 72 ?? ?? 00 70 08 28 ?? 00 00 06 13 05 11 05 2c 02 2b 59 1f 0c 28 ?? 00 00 0a 00 72 ?? ?? 00 70 28 ?? 00 00 0a 00 1b 13 06 2b 2a } //10
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}