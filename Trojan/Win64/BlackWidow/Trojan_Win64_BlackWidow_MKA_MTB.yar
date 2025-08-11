
rule Trojan_Win64_BlackWidow_MKA_MTB{
	meta:
		description = "Trojan:Win64/BlackWidow.MKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f af c8 8b c1 48 98 48 8b 8c 24 ?? ?? ?? ?? 48 2b c8 48 8b c1 0f b6 84 04 ?? ?? ?? ?? 8b 4c 24 68 33 c8 8b c1 48 63 4c 24 50 48 8b 54 24 58 88 04 0a e9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}