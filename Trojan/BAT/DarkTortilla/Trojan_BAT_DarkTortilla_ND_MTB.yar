
rule Trojan_BAT_DarkTortilla_ND_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.ND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 74 0b 00 00 1b 28 ?? ?? ?? 06 14 14 14 1a 20 ?? ?? ?? 64 28 54 02 00 06 16 8d ?? ?? ?? 01 14 14 14 28 ?? ?? ?? 0a 74 0b 00 00 1b } //5
		$a_01_1 = {45 64 33 77 31 2e 48 4b 73 2e 72 65 73 6f 75 72 63 65 73 } //1 Ed3w1.HKs.resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}