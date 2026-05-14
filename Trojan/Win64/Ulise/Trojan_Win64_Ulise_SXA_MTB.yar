
rule Trojan_Win64_Ulise_SXA_MTB{
	meta:
		description = "Trojan:Win64/Ulise.SXA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c0 4c 8d 05 ?? ?? ff ff 48 89 44 24 28 ?? ?? ?? 33 d2 89 44 24 20 33 c9 ff 15 ?? ?? ?? ?? 48 85 c0 74 ?? 48 8b c8 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}