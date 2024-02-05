
rule Trojan_Win64_IcedID_ADE_MTB{
	meta:
		description = "Trojan:Win64/IcedID.ADE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {49 83 c0 01 41 f7 ec d1 fa 8b c2 c1 e8 1f 03 d0 49 63 c4 41 83 c4 90 01 01 48 63 ca 48 6b c9 90 01 01 48 03 c8 48 8b 44 24 90 01 01 42 0f b6 8c 31 90 01 04 41 32 4c 00 90 01 01 43 88 4c 18 90 01 01 44 3b 64 24 90 01 01 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}