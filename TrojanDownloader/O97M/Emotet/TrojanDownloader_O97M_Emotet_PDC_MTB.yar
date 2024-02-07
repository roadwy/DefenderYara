
rule TrojanDownloader_O97M_Emotet_PDC_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.PDC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 6f 75 65 34 68 6a 6c 64 2e 76 62 73 } //01 00  c:\programdata\oue4hjld.vbs
		$a_01_1 = {63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 62 68 6e 61 73 6c 65 69 6c 2e 62 61 74 } //00 00  c:\programdata\bhnasleil.bat
	condition:
		any of ($a_*)
 
}