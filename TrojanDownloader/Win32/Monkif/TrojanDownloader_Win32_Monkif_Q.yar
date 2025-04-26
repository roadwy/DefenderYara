
rule TrojanDownloader_Win32_Monkif_Q{
	meta:
		description = "TrojanDownloader:Win32/Monkif.Q,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3e c6 85 f8 ff ff ff e9 e8 } //1
		$a_01_1 = {50 72 6f 33 65 73 73 33 32 46 69 72 73 74 00 } //1
		$a_03_2 = {8b 1e 85 db 0f 84 1f 00 00 00 8b 4e 04 83 c6 08 4b 0f b6 04 19 2a c2 81 c2 ?? 00 00 00 88 04 19 49 0f 85 ea ff ff ff eb d7 66 9d } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}