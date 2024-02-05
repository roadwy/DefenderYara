
rule TrojanDownloader_Win32_Banload_AAS{
	meta:
		description = "TrojanDownloader:Win32/Banload.AAS,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {62 74 6e 69 6e 78 43 6c 69 63 6b } //02 00 
		$a_01_1 = {62 74 6e 64 6f 78 43 6c 69 63 6b } //02 00 
		$a_01_2 = {62 74 6e 73 65 78 43 6c 69 63 6b } //01 00 
		$a_01_3 = {75 6e 69 74 63 72 69 70 74 } //00 00 
	condition:
		any of ($a_*)
 
}