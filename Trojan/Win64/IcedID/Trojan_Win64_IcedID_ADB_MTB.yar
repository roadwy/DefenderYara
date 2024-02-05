
rule Trojan_Win64_IcedID_ADB_MTB{
	meta:
		description = "Trojan:Win64/IcedID.ADB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 8b c7 49 f7 e0 41 ff c2 48 2b ca 48 d1 e9 48 03 ca 48 c1 e9 90 01 01 48 6b c1 90 01 01 4c 2b c0 42 90 01 05 41 30 43 90 01 01 41 90 00 } //01 00 
		$a_03_1 = {48 8b c7 41 ff c1 48 f7 e1 48 8b c1 48 2b c2 48 d1 e8 48 03 c2 48 c1 e8 90 01 01 48 6b c0 90 01 01 48 2b c8 0f b6 84 8c 90 01 04 41 30 40 90 01 01 41 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}