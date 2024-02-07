
rule Trojan_Win64_IcedID_BXF_MTB{
	meta:
		description = "Trojan:Win64/IcedID.BXF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 04 00 00 0a 00 "
		
	strings :
		$a_02_0 = {49 89 51 08 41 89 41 1c 0f b6 0a 83 e1 0f 4a 0f be 84 11 90 01 04 42 8a 8c 11 90 01 04 48 2b d0 8b 42 fc d3 e8 41 89 41 20 48 8d 42 04 49 89 51 08 8b 0a 49 89 41 08 41 89 49 24 49 83 e8 01 0f 85 ec 90 00 } //0a 00 
		$a_02_1 = {44 8b cb 41 8b ca 4c 8b c7 4c 33 15 90 01 04 83 e1 3f 49 d3 ca 48 8b d6 4d 85 d2 74 0f 48 8b 4c 24 60 49 8b c2 48 89 4c 24 20 eb ae 90 00 } //01 00 
		$a_01_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00  DllRegisterServer
		$a_01_3 = {61 71 69 6c 6b 74 64 65 76 6f 7a 61 66 6d 74 } //00 00  aqilktdevozafmt
	condition:
		any of ($a_*)
 
}