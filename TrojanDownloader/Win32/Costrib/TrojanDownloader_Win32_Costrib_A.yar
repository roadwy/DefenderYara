
rule TrojanDownloader_Win32_Costrib_A{
	meta:
		description = "TrojanDownloader:Win32/Costrib.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 31 33 38 2e 32 30 34 2e 31 37 31 2e 31 30 38 2f 42 78 6a 4c 35 69 4b 6c 64 38 2e 7a 69 70 } //5 http://138.204.171.108/BxjL5iKld8.zip
	condition:
		((#a_01_0  & 1)*5) >=5
 
}