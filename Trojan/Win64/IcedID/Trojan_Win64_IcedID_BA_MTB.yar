
rule Trojan_Win64_IcedID_BA_MTB{
	meta:
		description = "Trojan:Win64/IcedID.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 03 00 "
		
	strings :
		$a_01_0 = {48 89 4c 24 08 48 83 ec 28 eb 00 48 8b 44 24 30 48 89 44 24 08 eb 28 48 8b 44 24 08 48 ff c0 eb d3 8a 09 88 08 eb } //01 00 
		$a_01_1 = {69 79 61 68 73 75 66 79 67 61 73 75 66 69 68 6b 61 6a 73 6b 66 75 68 61 73 79 68 66 61 6a 61 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_BA_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 8b c1 0f b7 4c 24 90 01 01 3a d2 74 90 01 01 66 89 44 24 90 01 01 48 90 01 07 66 3b c9 74 90 01 01 33 c8 8b c1 66 3b c9 74 90 00 } //01 00 
		$a_03_1 = {8b c0 3a ff 74 90 01 01 8b 44 24 90 01 01 f7 b4 24 90 01 04 66 3b c9 74 90 01 01 89 84 24 90 01 04 33 d2 66 3b f6 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}