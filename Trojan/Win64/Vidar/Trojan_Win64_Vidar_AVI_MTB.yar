
rule Trojan_Win64_Vidar_AVI_MTB{
	meta:
		description = "Trojan:Win64/Vidar.AVI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 ff c2 45 69 c0 ?? ?? ?? ?? 8b c8 c1 e9 18 33 c8 69 c9 ?? ?? ?? ?? 44 33 c1 48 3b d3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}