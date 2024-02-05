
rule TrojanDownloader_Win32_Banker_AC{
	meta:
		description = "TrojanDownloader:Win32/Banker.AC,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {43 59 76 61 52 36 6d 90 02 40 2f 69 6e 69 63 69 6f 90 02 80 52 75 6e 44 6c 6c 33 32 2e 65 78 65 90 02 40 2c 6f 6e 6c 69 66 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}