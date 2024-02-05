
rule TrojanDownloader_Win64_IcedID_ZZ{
	meta:
		description = "TrojanDownloader:Win64/IcedID.ZZ,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 8a 04 33 41 0f b6 d3 44 8d 42 01 83 e2 03 41 83 e0 03 42 8a 4c 85 e0 02 4c 95 e0 32 c1 42 8b 4c 85 e0 41 88 04 1b 83 e1 07 8b 44 95 e0 49 ff c3 d3 c8 ff c0 89 44 95 e0 83 e0 07 8a c8 42 8b 44 85 e0 d3 c8 ff c0 42 89 44 85 e0 48 8b 5d c8 4c 3b 5d d0 73 06 48 8b 75 c0 eb a4 } //00 00 
	condition:
		any of ($a_*)
 
}