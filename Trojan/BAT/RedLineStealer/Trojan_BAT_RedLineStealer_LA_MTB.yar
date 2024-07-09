
rule Trojan_BAT_RedLineStealer_LA_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.LA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 09 11 06 9c 06 08 91 06 09 91 58 ?? ?? ?? ?? ?? 5d 13 07 02 11 05 8f 1d ?? ?? ?? 25 ?? ?? ?? ?? ?? 06 11 07 91 61 d2 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}