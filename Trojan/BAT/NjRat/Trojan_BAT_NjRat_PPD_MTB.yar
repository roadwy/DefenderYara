
rule Trojan_BAT_NjRat_PPD_MTB{
	meta:
		description = "Trojan:BAT/NjRat.PPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 04 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 6a 03 28 ?? ?? ?? 0a 04 08 5d 6c 58 28 ?? ?? ?? 0a b8 6e da 0b 06 07 b7 28 ?? ?? ?? 0a 8c ?? ?? ?? 01 28 ?? ?? ?? 0a 0a 11 04 17 d6 13 04 11 04 09 31 c0 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}