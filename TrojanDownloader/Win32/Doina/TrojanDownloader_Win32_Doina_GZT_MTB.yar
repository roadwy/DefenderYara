
rule TrojanDownloader_Win32_Doina_GZT_MTB{
	meta:
		description = "TrojanDownloader:Win32/Doina.GZT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8b d1 57 8b 7c 24 90 01 01 33 c0 c1 e9 90 01 01 f3 ab 8b ca 83 e1 90 01 01 f3 aa 5f c3 90 00 } //01 00 
		$a_01_1 = {46 69 6c 65 41 70 69 2e 67 79 61 6f 74 74 2e 74 6f 70 } //01 00 
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //00 00 
	condition:
		any of ($a_*)
 
}