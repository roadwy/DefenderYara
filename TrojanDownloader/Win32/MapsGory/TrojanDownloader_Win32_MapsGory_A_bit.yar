
rule TrojanDownloader_Win32_MapsGory_A_bit{
	meta:
		description = "TrojanDownloader:Win32/MapsGory.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {c7 45 ec 73 55 dc 05 8d 4d ec 51 e8 ?? ?? ?? ff a3 ?? ?? ?? 00 8b 15 ?? ?? ?? 00 52 e8 ?? ?? ?? ff } //1
		$a_01_1 = {68 74 74 70 3a 2f 2f 00 2f 6c 6f 61 64 65 72 2f 63 6f 6d 65 74 61 2e 65 78 65 00 } //1
		$a_01_2 = {00 61 62 61 6e 64 6f 6e 20 61 62 69 6c 69 74 79 20 61 62 6c 65 20 61 62 6f 75 74 20 61 62 6f 76 65 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}