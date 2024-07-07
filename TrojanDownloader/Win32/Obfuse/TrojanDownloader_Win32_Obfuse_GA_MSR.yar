
rule TrojanDownloader_Win32_Obfuse_GA_MSR{
	meta:
		description = "TrojanDownloader:Win32/Obfuse.GA!MSR,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b c1 80 f3 78 99 f7 7c 24 20 8a 04 2a 8a 14 31 32 d0 88 14 31 41 3b cf } //2
		$a_01_1 = {63 68 78 73 61 70 72 66 79 77 6e } //1 chxsaprfywn
		$a_01_2 = {48 69 73 74 6f 72 79 20 6f 66 20 54 69 62 65 74 2d 4c 61 64 61 6b 68 20 52 65 6c 61 74 69 6f 6e 73 20 61 6e 64 20 54 68 65 69 72 20 4d 6f 64 65 72 6e 20 49 6d 70 6c 69 63 61 74 69 6f 6e 73 2e 64 6f 63 78 } //1 History of Tibet-Ladakh Relations and Their Modern Implications.docx
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}