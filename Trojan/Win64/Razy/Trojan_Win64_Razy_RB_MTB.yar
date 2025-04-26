
rule Trojan_Win64_Razy_RB_MTB{
	meta:
		description = "Trojan:Win64/Razy.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 63 44 24 40 48 3d 00 06 03 00 73 26 48 63 44 24 40 48 8d 0d ?? ?? 00 00 0f b6 04 01 35 ad 00 00 00 48 63 4c 24 40 48 8d 15 ?? ?? 00 00 88 04 0a eb c3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}