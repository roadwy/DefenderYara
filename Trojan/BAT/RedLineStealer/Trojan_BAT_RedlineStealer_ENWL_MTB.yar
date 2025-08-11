
rule Trojan_BAT_RedlineStealer_ENWL_MTB{
	meta:
		description = "Trojan:BAT/RedlineStealer.ENWL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {6c 5b 13 22 1f 50 13 53 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 11 21 1f 64 5d 58 13 23 22 a0 1a cf 3f 11 21 6b 5a 13 24 11 55 1f 72 91 1f 56 58 13 53 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}