
rule TrojanDownloader_Win64_IcedID_CA_MTB{
	meta:
		description = "TrojanDownloader:Win64/IcedID.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b 44 24 ?? 8a 08 88 4c 24 ?? c7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? 48 8b 44 24 ?? 48 05 01 00 00 00 48 89 44 24 ?? c7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? 8a 4c 24 ?? 0f b6 d1 83 ea ?? 88 54 24 ?? c7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? 8a 4c 24 ?? 44 0f b6 c1 41 c1 e0 04 44 88 44 24 ?? c7 44 24 ?? ?? ?? ?? ?? 8a 4c 24 ?? 88 4c 24 ?? c7 44 24 ?? ?? ?? ?? ?? 48 8b 44 24 ?? 8a 08 88 4c 24 ?? c7 44 24 ?? ?? ?? ?? ?? 48 8b 44 24 ?? 48 05 01 00 00 00 48 89 44 24 ?? c7 44 24 ?? ?? ?? ?? ?? 8a 4c 24 ?? 44 0f b6 c9 41 83 e9 ?? 44 88 4c 24 } //1
		$a_03_1 = {45 09 d3 44 88 5c 24 ?? c7 44 24 ?? ?? ?? ?? ?? 8a 4c 24 ?? 44 0f b6 d1 8a 4c 24 ?? 0f b6 f1 44 31 d6 40 88 74 24 ?? c7 44 24 ?? ?? ?? ?? ?? 8a 4c 24 ?? 80 c1 01 88 4c 24 ?? c7 44 24 ?? ?? ?? ?? ?? 8a 4c 24 ?? 48 8b 44 24 ?? 88 08 c7 44 24 ?? ?? ?? ?? ?? 48 8b 44 24 ?? 48 05 01 00 00 00 48 89 44 24 ?? c7 44 24 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}