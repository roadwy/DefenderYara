
rule TrojanDownloader_Win64_IcedID_ZW{
	meta:
		description = "TrojanDownloader:Win64/IcedID.ZW,SIGNATURE_TYPE_PEHSTR_EXT,65 00 65 00 02 00 00 "
		
	strings :
		$a_00_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_03_1 = {83 e2 03 41 83 e0 03 [0-01] 8a ?? ?? ?? [0-01] 02 ?? ?? ?? [0-01] 32 [0-02] 42 8b 4c ?? ?? 41 88 04 1b 83 e1 07 8b 44 ?? ?? 49 ff c3 d3 c8 ff c0 89 44 ?? ?? 83 e0 07 8a c8 42 8b 44 ?? ?? d3 c8 ff c0 42 89 44 ?? ?? 48 8b [0-03] 4c 3b [0-03] 73 } //100
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*100) >=101
 
}