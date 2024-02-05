
rule Trojan_Win64_AresLdr_MA_MTB{
	meta:
		description = "Trojan:Win64/AresLdr.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {44 03 c1 41 8b c8 03 d1 8b ca 8b 15 90 01 04 0f af 15 90 01 04 44 8b 05 90 01 04 44 03 c1 41 8b c8 03 d1 8b ca 8b 15 90 01 04 0f af 15 90 01 04 2b ca 03 0d 90 01 04 2b 0d 90 01 04 48 63 c9 48 8b 94 24 70 03 00 00 88 04 0a e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}