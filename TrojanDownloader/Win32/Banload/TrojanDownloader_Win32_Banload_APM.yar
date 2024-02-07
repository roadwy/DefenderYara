
rule TrojanDownloader_Win32_Banload_APM{
	meta:
		description = "TrojanDownloader:Win32/Banload.APM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 69 62 7a 69 70 73 2e 65 78 65 00 } //01 00 
		$a_01_1 = {2f 6d 65 6d 62 72 6f 73 2e 70 68 70 00 } //01 00 
		$a_00_2 = {7b 4f 55 34 35 4d 44 33 46 2d 52 56 32 4d 2d 45 47 57 30 2d 32 57 32 49 2d 4f 48 57 57 57 48 31 4e 48 37 47 30 7d } //00 00  {OU45MD3F-RV2M-EGW0-2W2I-OHWWWH1NH7G0}
	condition:
		any of ($a_*)
 
}