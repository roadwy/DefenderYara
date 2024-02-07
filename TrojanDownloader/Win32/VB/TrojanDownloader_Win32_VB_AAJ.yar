
rule TrojanDownloader_Win32_VB_AAJ{
	meta:
		description = "TrojanDownloader:Win32/VB.AAJ,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 0a 00 "
		
	strings :
		$a_00_0 = {5c 00 4d 00 41 00 53 00 54 00 45 00 52 00 5c 00 55 00 4e 00 49 00 5f 00 53 00 4f 00 46 00 54 00 5c 00 41 00 44 00 57 00 41 00 52 00 41 00 5c 00 73 00 69 00 6c 00 65 00 6e 00 74 00 5f 00 6c 00 6f 00 61 00 64 00 65 00 72 00 5c 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 31 00 2e 00 76 00 62 00 70 00 } //0a 00  \MASTER\UNI_SOFT\ADWARA\silent_loader\Project1.vbp
		$a_00_1 = {74 00 6d 00 72 00 73 00 72 00 2e 00 65 00 78 00 65 00 } //0a 00  tmrsr.exe
		$a_01_2 = {43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 00 00 00 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 } //00 00 
	condition:
		any of ($a_*)
 
}