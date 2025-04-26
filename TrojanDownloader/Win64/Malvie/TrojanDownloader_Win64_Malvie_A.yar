
rule TrojanDownloader_Win64_Malvie_A{
	meta:
		description = "TrojanDownloader:Win64/Malvie.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {77 00 33 00 c7 ?? ?? ?? 2e 00 6f 00 c7 ?? ?? ?? 72 00 67 00 } //1
		$a_03_1 = {47 00 45 00 c7 ?? ?? 54 00 00 00 ff } //1
		$a_03_2 = {73 00 3a 00 [0-0a] 2f 00 2f 00 e8 ?? ?? 00 00 81 3b 68 74 74 70 } //1
		$a_03_3 = {ba 80 fc ec 04 e8 90 0a 20 00 0d 0a 41 ?? 06 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}