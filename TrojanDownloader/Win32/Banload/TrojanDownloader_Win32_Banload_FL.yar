
rule TrojanDownloader_Win32_Banload_FL{
	meta:
		description = "TrojanDownloader:Win32/Banload.FL,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6e 70 72 65 74 2e 65 78 65 00 } //1
		$a_01_1 = {66 72 65 65 77 65 62 74 6f 77 6e 2e 63 6f 6d 2f 77 65 6e 76 76 63 72 2f 69 70 6e 65 74 2e 65 78 65 00 } //1
		$a_03_2 = {0d 80 00 00 00 50 6a ec a1 ?? ?? ?? 00 53 e8 ?? ?? ?? ?? ba 64 01 45 00 b8 88 01 45 00 e8 ?? ?? ?? ?? 84 c0 74 0c 6a 00 68 b8 01 45 00 e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}