
rule TrojanDownloader_Win32_Banload_VT{
	meta:
		description = "TrojanDownloader:Win32/Banload.VT,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c6 45 f3 01 eb 04 43 4e 75 b5 80 7d f3 00 75 0a 8b c7 8b 55 f4 } //1
		$a_01_1 = {2e 6a 70 67 20 48 54 54 50 2f 31 2e 31 0d 0a 43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a } //1 樮杰䠠呔⽐⸱റ䌊湯整瑮吭灹㩥
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}