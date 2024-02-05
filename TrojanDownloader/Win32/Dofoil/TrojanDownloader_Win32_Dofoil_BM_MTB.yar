
rule TrojanDownloader_Win32_Dofoil_BM_MTB{
	meta:
		description = "TrojanDownloader:Win32/Dofoil.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {81 e6 ff 00 00 00 33 ff 89 35 90 01 04 81 fa 56 0e 00 00 8a 9e 90 01 04 0f 44 c7 a3 90 01 04 8a 81 90 01 04 88 86 90 01 04 88 5c 24 0f 88 99 90 01 04 81 fa ab 0c 00 00 75 90 00 } //01 00 
		$a_02_1 = {30 04 3e 4e 79 f5 8b 8c 24 30 08 00 00 5f 5e 5d 5b 33 cc e8 90 01 04 81 c4 24 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}