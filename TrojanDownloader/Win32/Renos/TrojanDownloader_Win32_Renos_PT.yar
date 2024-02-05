
rule TrojanDownloader_Win32_Renos_PT{
	meta:
		description = "TrojanDownloader:Win32/Renos.PT,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 c0 81 c0 4d 5a 50 00 } //01 00 
		$a_01_1 = {b8 af ba ff ff f7 d0 } //02 00 
		$a_03_2 = {fb ff ff f7 90 01 01 83 90 01 01 04 c7 90 01 01 00 00 00 00 83 90 01 01 04 75 f2 ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}