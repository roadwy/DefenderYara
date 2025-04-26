
rule TrojanDownloader_BAT_Blocker_AAT_MTB{
	meta:
		description = "TrojanDownloader:BAT/Blocker.AAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {30 4c 02 7b ?? 00 00 04 06 02 7b ?? 00 00 04 02 7b ?? 00 00 04 03 28 ?? 00 00 0a 02 02 7b ?? 00 00 04 03 58 7d ?? 00 00 04 2a 02 7b ?? 00 00 04 02 02 7b ?? 00 00 04 0c 08 17 58 7d ?? 00 00 04 08 } //5
		$a_00_1 = {24 65 38 30 63 66 37 34 66 2d 36 33 62 66 2d 34 64 36 62 2d 38 33 36 34 2d 63 37 62 61 61 61 64 33 61 32 65 63 } //1 $e80cf74f-63bf-4d6b-8364-c7baaad3a2ec
		$a_00_2 = {43 6f 6e 73 6f 6c 65 41 70 70 34 38 2e 65 78 65 } //1 ConsoleApp48.exe
	condition:
		((#a_03_0  & 1)*5+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=7
 
}