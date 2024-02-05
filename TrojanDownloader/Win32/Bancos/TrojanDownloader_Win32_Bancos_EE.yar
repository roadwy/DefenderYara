
rule TrojanDownloader_Win32_Bancos_EE{
	meta:
		description = "TrojanDownloader:Win32/Bancos.EE,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {83 c4 3c 83 c9 ff 33 c0 41 83 f9 40 7e 02 33 c9 8a 91 90 01 03 00 30 90 90 90 01 03 00 40 3d 00 08 00 00 7c e4 90 00 } //01 00 
		$a_02_1 = {b2 68 b1 3a 80 bc 05 90 01 04 67 75 1c 80 bc 05 90 01 03 ff 74 75 12 38 94 90 01 05 75 09 38 8c 90 01 05 74 07 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}