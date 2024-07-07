
rule TrojanDownloader_Win32_Kepma_A{
	meta:
		description = "TrojanDownloader:Win32/Kepma.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {77 65 6d 61 6b 65 2e 61 64 6e 74 6f 70 2e 63 6f 6d 2f } //1 wemake.adntop.com/
		$a_02_1 = {70 61 72 74 90 01 02 00 00 63 6f 64 65 00 00 00 00 44 45 46 41 55 4c 54 5f 00 00 90 00 } //1
		$a_00_2 = {77 65 6d 61 6b 65 70 70 6f 70 5c 63 6e 73 2e 64 61 74 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}