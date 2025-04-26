
rule TrojanDownloader_Win32_Astaroth_KH{
	meta:
		description = "TrojanDownloader:Win32/Astaroth.KH,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {6d 00 73 00 68 00 74 00 61 00 20 00 } //1 mshta 
		$a_00_1 = {6a 00 61 00 76 00 61 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 76 00 61 00 72 00 20 00 } //1 javascript:var 
		$a_02_2 = {74 00 72 00 79 00 [0-04] 67 00 65 00 74 00 6f 00 62 00 6a 00 65 00 63 00 74 00 [0-ff] 63 00 61 00 74 00 63 00 68 00 28 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}