
rule Trojan_Win64_Dridex_BVV_MTB{
	meta:
		description = "Trojan:Win64/Dridex.BVV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d6 48 8d 4d d0 48 8b d8 e8 ?? ?? ?? ?? 8b d6 48 8d 4d e8 40 8a 38 40 32 3b e8 ?? ?? ?? ?? ff c6 40 88 38 41 3b f7 7c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}