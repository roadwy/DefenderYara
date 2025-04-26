
rule TrojanDownloader_Win32_Bedep_A{
	meta:
		description = "TrojanDownloader:Win32/Bedep.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c1 c2 03 66 83 f8 41 72 0e 66 83 f8 5a 77 08 0f b7 c0 83 c8 20 eb 03 } //1
		$a_01_1 = {8b 41 3c 6a 01 8b 44 08 28 51 03 c1 ff d0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}