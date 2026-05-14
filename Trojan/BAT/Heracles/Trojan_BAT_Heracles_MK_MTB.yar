
rule Trojan_BAT_Heracles_MK_MTB{
	meta:
		description = "Trojan:BAT/Heracles.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 03 00 00 "
		
	strings :
		$a_03_0 = {26 16 2a 28 ?? ?? ?? 06 12 01 7b ?? ?? ?? 04 11 07 08 09 12 08 28 ?? ?? ?? 06 2d 2a 12 } //20
		$a_03_1 = {11 05 11 06 9a 0c 08 28 ?? ?? ?? 0a 2d 23 08 6f ?? ?? ?? 0a 18 30 03 08 2b 08 08 16 18 6f ?? ?? ?? 0a 0d 07 09 1f 10 28 0d 00 00 0a 6f 0e 00 00 0a } //15
		$a_03_2 = {16 0c 2b 04 08 17 58 0c 08 20 ?? ?? ?? 00 32 f4 28 ?? ?? ?? 06 06 59 07 } //5
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*15+(#a_03_2  & 1)*5) >=40
 
}