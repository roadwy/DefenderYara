
rule TrojanDownloader_Win32_Chepvil_N{
	meta:
		description = "TrojanDownloader:Win32/Chepvil.N,SIGNATURE_TYPE_PEHSTR,0b 00 0b 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 25 73 2f 66 74 70 2f 67 2e 70 68 70 } //0a 00 
		$a_01_1 = {0f be 45 00 0f be 75 01 33 f0 b8 00 00 00 00 76 14 } //00 00 
	condition:
		any of ($a_*)
 
}