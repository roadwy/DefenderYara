
rule Trojan_Win64_Redline_RAN_MTB{
	meta:
		description = "Trojan:Win64/Redline.RAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 00 89 85 98 00 00 00 48 8b 45 48 48 8b 8d c8 00 00 00 48 03 c8 48 8b c1 0f b6 00 88 85 9c 00 00 00 0f b6 85 9c 00 00 00 33 85 98 00 00 00 48 8b 4d ?? 48 8b 95 c8 00 00 00 48 03 d1 48 8b ca 88 01 e9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}