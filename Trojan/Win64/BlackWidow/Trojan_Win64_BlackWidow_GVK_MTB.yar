
rule Trojan_Win64_BlackWidow_GVK_MTB{
	meta:
		description = "Trojan:Win64/BlackWidow.GVK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b d1 8b ca 48 63 c9 48 0f af c1 0f b6 44 04 78 8b 4c 24 4c 33 c8 8b c1 48 63 4c 24 24 48 8b 54 24 60 88 04 0a eb } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}