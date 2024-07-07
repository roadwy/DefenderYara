
rule TrojanDownloader_Win64_IcedID_ZX{
	meta:
		description = "TrojanDownloader:Win64/IcedID.ZX,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {56 48 81 ec b0 00 00 00 31 c0 89 c1 c7 90 01 07 8b 90 01 05 35 90 01 04 89 90 01 05 c7 90 01 0a 8b 90 01 05 89 90 01 03 c7 90 01 0a 8b 90 01 05 35 90 01 04 89 90 01 05 c7 90 01 0a 48 8b 90 01 05 8b 90 01 05 41 89 90 01 01 48 89 90 01 03 4c 89 90 01 01 41 b8 00 30 00 00 41 b9 04 00 00 00 4c 8b 90 01 03 41 ff d2 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}