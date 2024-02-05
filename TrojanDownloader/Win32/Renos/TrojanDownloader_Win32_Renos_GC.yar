
rule TrojanDownloader_Win32_Renos_GC{
	meta:
		description = "TrojanDownloader:Win32/Renos.GC,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 83 38 7b 75 0e } //01 00 
		$a_01_1 = {c6 47 03 3d 80 f1 a5 } //01 00 
		$a_01_2 = {35 a5 00 00 00 3d 69 ff ff ff 75 } //00 00 
	condition:
		any of ($a_*)
 
}