
rule Trojan_BAT_DiscordStealer_CXFW_MTB{
	meta:
		description = "Trojan:BAT/DiscordStealer.CXFW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {12 03 28 12 00 00 0a 0c 00 07 08 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 0b 00 12 03 28 14 00 00 0a 13 04 11 04 } //1
		$a_01_1 = {55 00 6b 00 34 00 33 00 75 00 66 00 30 00 42 00 4c 00 59 00 67 00 3d 00 } //1 Uk43uf0BLYg=
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}