
rule Trojan_Win64_Latrodectus_PB_MTB{
	meta:
		description = "Trojan:Win64/Latrodectus.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {ba 01 00 00 00 48 6b d2 2a 0f be 94 14 90 01 04 0f af ca 48 63 c9 48 2b c1 0f b6 44 04 90 01 01 8b 8c 24 90 01 04 33 c8 8b c1 48 63 4c 24 90 01 01 48 8b 54 24 90 01 01 88 04 0a e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}