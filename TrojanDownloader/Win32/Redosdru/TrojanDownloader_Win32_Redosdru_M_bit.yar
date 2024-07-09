
rule TrojanDownloader_Win32_Redosdru_M_bit{
	meta:
		description = "TrojanDownloader:Win32/Redosdru.M!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {81 e3 ff 00 00 80 79 08 4b 81 cb 00 ff ff ff 43 0f b6 14 03 30 14 2f 47 3b 7c 24 1c 72 a7 } //2
		$a_03_1 = {51 c6 44 24 ?? 4b c6 44 24 ?? 6f c6 44 24 ?? 74 c6 44 24 ?? 68 c6 44 24 ?? 65 c6 44 24 ?? 72 } //1
		$a_03_2 = {56 c6 44 24 ?? 43 c6 44 24 ?? 61 c6 44 24 ?? 6f c6 44 24 ?? 33 c6 44 24 ?? 36 c6 44 24 ?? 30 } //1
		$a_03_3 = {6a 04 68 00 30 00 00 8b f8 57 53 ff 15 ?? ?? ?? 00 53 8b e8 8d 44 24 ?? 50 57 55 56 ff 15 ?? ?? ?? 00 56 ff 15 ?? ?? ?? 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}