
rule TrojanDownloader_Win32_Banload_VR{
	meta:
		description = "TrojanDownloader:Win32/Banload.VR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 65 72 65 6e 63 69 61 64 6f 72 54 69 6d 65 72 } //01 00  GerenciadorTimer
		$a_01_1 = {6d 73 63 6f 6e 66 69 67 54 69 6d 65 72 } //01 00  msconfigTimer
		$a_03_2 = {66 69 72 65 66 6f 78 90 01 07 55 72 6c 41 63 65 73 73 61 90 01 07 42 41 4e 53 41 4e 90 01 09 4c 41 52 41 4e 4a 41 54 69 6d 65 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}