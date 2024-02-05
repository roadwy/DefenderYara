
rule TrojanDownloader_Win32_Dofoil_AT{
	meta:
		description = "TrojanDownloader:Win32/Dofoil.AT,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {81 fa f7 13 00 00 75 90 01 01 6a 00 90 00 } //01 00 
		$a_03_1 = {b1 6d b0 6c 68 68 91 47 00 88 90 02 05 c6 90 01 05 73 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}