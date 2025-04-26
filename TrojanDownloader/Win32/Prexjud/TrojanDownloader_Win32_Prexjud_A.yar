
rule TrojanDownloader_Win32_Prexjud_A{
	meta:
		description = "TrojanDownloader:Win32/Prexjud.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 45 78 65 63 50 72 69 2e 64 6c 6c 00 68 69 67 68 00 45 78 65 63 57 61 69 74 00 } //1
		$a_01_1 = {5c 57 69 6e 64 6f 77 73 20 55 70 64 61 74 65 72 2e 6c 6e 6b 00 } //1
		$a_01_2 = {5c 4a 44 73 74 61 72 74 2e 65 78 65 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}