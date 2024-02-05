
rule TrojanDownloader_Win64_IcedID_VP_MTB{
	meta:
		description = "TrojanDownloader:Win64/IcedID.VP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {41 0f b6 d3 44 8d 42 01 83 e2 90 01 01 41 83 e0 90 01 01 42 8a 44 84 40 02 44 94 40 43 32 04 33 42 8b 4c 84 40 41 88 04 1b 83 e1 07 8b 44 94 40 49 ff c3 d3 c8 ff c0 89 44 94 40 83 e0 90 01 01 8a c8 42 8b 44 84 40 d3 c8 ff c0 42 89 44 84 40 48 8b 5c 24 28 4c 3b 5c 24 30 73 07 4c 8b 74 24 20 eb a3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}