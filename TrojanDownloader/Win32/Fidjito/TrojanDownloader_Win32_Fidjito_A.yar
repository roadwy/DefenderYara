
rule TrojanDownloader_Win32_Fidjito_A{
	meta:
		description = "TrojanDownloader:Win32/Fidjito.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {53 6a 4f 57 ff d6 57 ff 15 ?? ?? ?? ?? 69 c0 60 ea 00 00 53 6a 50 57 89 45 f4 ff d6 } //1
		$a_03_1 = {83 c4 2c 33 c0 80 b0 ?? ?? ?? ?? ?? 40 83 f8 0f 7c f3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}