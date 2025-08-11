
rule Trojan_Win64_BlackWidow_GVT_MTB{
	meta:
		description = "Trojan:Win64/BlackWidow.GVT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {48 0f af c8 48 8b c1 0f b6 84 04 ?? ?? ?? ?? 8b 4c 24 68 33 c8 8b c1 48 63 4c 24 50 48 8b 54 24 58 88 04 0a } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}