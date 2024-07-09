
rule TrojanDownloader_Win32_Cutwail_gen_D{
	meta:
		description = "TrojanDownloader:Win32/Cutwail.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {2b cf 49 3b cb 72 0a 8b c1 2b c3 8a 14 30 30 14 31 } //1
		$a_03_1 = {80 38 4d 75 ?? 80 78 01 5a 75 ?? 80 78 50 69 75 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}