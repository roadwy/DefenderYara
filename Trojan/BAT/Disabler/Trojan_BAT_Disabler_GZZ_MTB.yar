
rule Trojan_BAT_Disabler_GZZ_MTB{
	meta:
		description = "Trojan:BAT/Disabler.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {2d 47 06 02 1f 2e 28 ?? ?? ?? 06 12 01 fe 15 0b 00 00 02 25 17 12 01 28 ?? ?? ?? 06 26 25 15 1a 15 14 14 7e 14 00 00 0a 14 14 14 14 28 ?? ?? ?? 06 26 20 d0 07 00 00 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 26 06 28 ?? ?? ?? 06 26 2a } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}