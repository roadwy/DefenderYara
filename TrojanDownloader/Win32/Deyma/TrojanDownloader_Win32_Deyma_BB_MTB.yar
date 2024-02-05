
rule TrojanDownloader_Win32_Deyma_BB_MTB{
	meta:
		description = "TrojanDownloader:Win32/Deyma.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {33 c1 2b f0 8d 45 f8 50 e8 90 02 04 ff 4d f4 0f 85 90 00 } //01 00 
		$a_03_1 = {3d 50 15 00 00 75 0c 8b 0d 90 02 04 89 0d 90 02 04 40 3d 90 02 04 7c 90 00 } //01 00 
		$a_01_2 = {81 fe 6e 27 87 01 7f 0d 46 81 fe f6 ea 2b 33 0f 8c } //00 00 
	condition:
		any of ($a_*)
 
}