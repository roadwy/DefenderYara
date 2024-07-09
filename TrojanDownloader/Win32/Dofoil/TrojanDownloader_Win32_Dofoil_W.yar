
rule TrojanDownloader_Win32_Dofoil_W{
	meta:
		description = "TrojanDownloader:Win32/Dofoil.W,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_03_0 = {73 6d 6b 00 90 09 06 00 c7 87 ?? 00 00 00 } //1
		$a_01_1 = {60 89 c5 89 d3 8b 7b 3c 8b 7c 1f 78 01 df } //1
		$a_01_2 = {81 c7 00 12 00 00 66 c7 07 57 6f 66 c7 47 02 72 6b } //1
		$a_01_3 = {81 7d 00 40 1a cd 00 74 09 81 7d 00 46 46 14 70 75 05 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}