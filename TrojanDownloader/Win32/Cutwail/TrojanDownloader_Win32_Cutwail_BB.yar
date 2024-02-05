
rule TrojanDownloader_Win32_Cutwail_BB{
	meta:
		description = "TrojanDownloader:Win32/Cutwail.BB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a bf 68 ff cf ff ff f7 14 24 f7 54 24 04 } //01 00 
		$a_01_1 = {88 04 31 86 c3 41 42 83 fa 04 72 } //00 00 
	condition:
		any of ($a_*)
 
}