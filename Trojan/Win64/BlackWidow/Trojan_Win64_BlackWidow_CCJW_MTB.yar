
rule Trojan_Win64_BlackWidow_CCJW_MTB{
	meta:
		description = "Trojan:Win64/BlackWidow.CCJW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 98 48 89 84 24 ?? ?? ?? ?? 33 d2 48 8b 8c 24 ?? ?? ?? ?? 48 8b c1 48 8b 8c 24 ?? ?? ?? ?? 48 f7 f1 0f b6 84 04 ?? ?? ?? ?? 8b 4c 24 58 33 c8 8b c1 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}