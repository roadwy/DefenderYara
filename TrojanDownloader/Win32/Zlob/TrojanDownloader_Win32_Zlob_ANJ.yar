
rule TrojanDownloader_Win32_Zlob_ANJ{
	meta:
		description = "TrojanDownloader:Win32/Zlob.ANJ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {8d 45 fc 50 8d 45 10 50 ?? 68 3f 00 0f 00 ?? ?? ?? 68 ?? ?? 40 00 ff 75 0c ff 15 ?? ?? 40 00 ff 75 0c 8b ?? ?? ?? 40 00 ff ?? 8d 45 fc 50 8d 45 0c 50 ?? 68 3f 00 0f 00 ?? ?? ?? 68 ?? ?? 40 00 ff 75 10 } //1
		$a_03_1 = {43 4c 53 49 44 [0-10] 4e 56 69 64 65 6f 43 6f 64 65 6b 2e 43 68 6c } //1
		$a_03_2 = {54 68 69 73 20 77 69 6c 6c 20 69 6e 73 74 61 6c 6c 20 56 63 6f 64 65 63 20 76 65 72 20 33 2e 31 35 2e 20 44 6f 20 79 6f 75 20 77 69 73 68 20 74 6f 20 63 6f 6e 74 69 6e 75 65 3f [0-10] 56 63 6f 64 65 63 20 76 65 72 20 33 2e 31 35 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}