
rule TrojanDownloader_Win32_Banload_BCF{
	meta:
		description = "TrojanDownloader:Win32/Banload.BCF,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 44 30 ff 33 c3 89 45 ?? 3b 7d ?? 7c 0f 8b 45 ?? 05 ff 00 00 00 2b c7 89 45 ?? eb 03 } //1
		$a_01_1 = {30 32 31 43 30 33 30 45 32 39 41 30 33 43 45 42 31 37 42 43 30 33 31 42 32 38 39 38 33 43 45 37 30 34 34 34 33 32 35 35 46 42 31 43 44 33 30 43 30 46 34 39 46 39 32 30 30 44 32 34 44 46 31 34 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}