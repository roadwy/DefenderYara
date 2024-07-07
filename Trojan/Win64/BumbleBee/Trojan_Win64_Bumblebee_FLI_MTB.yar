
rule Trojan_Win64_Bumblebee_FLI_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.FLI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 63 c9 48 8b 54 24 40 0f b6 0c 0a 0f af c1 6b 0d 84 b1 11 00 03 48 63 c9 48 8b 54 24 48 0f b6 0c 0a 03 c1 0f b6 4c 24 03 33 c1 0f b6 0c 24 48 63 c9 48 8b 94 24 90 01 04 89 04 8a 0f b6 04 24 fe c8 88 04 24 0f b6 44 24 01 0f b6 0c 24 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}