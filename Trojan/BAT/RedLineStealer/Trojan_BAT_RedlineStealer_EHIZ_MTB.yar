
rule Trojan_BAT_RedlineStealer_EHIZ_MTB{
	meta:
		description = "Trojan:BAT/RedlineStealer.EHIZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 07 20 d2 04 00 00 5a 61 0a 06 07 ?? ?? ?? ?? ?? 5a ?? ?? ?? ?? ?? 5d 58 0a 06 17 62 06 1f 1f 63 60 0a 07 17 58 0b 07 1f 0a 32 d4 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}