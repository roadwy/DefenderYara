
rule TrojanDownloader_O97M_Ursnif_A_MSR{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.A!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 05 00 03 00 00 "
		
	strings :
		$a_00_0 = {45 78 65 63 75 74 65 43 6f 6d 6d 61 6e 64 20 22 43 3a 5c 44 69 73 6b 44 72 69 76 65 5c 31 5c 56 6f 6c 75 6d 65 5c 42 61 63 6b 46 69 6c 65 73 5c 65 72 72 6f 72 66 69 78 2e 62 61 74 } //5 ExecuteCommand "C:\DiskDrive\1\Volume\BackFiles\errorfix.bat
		$a_02_1 = {2e 70 68 70 20 22 20 26 20 45 6e 76 69 72 6f 6e 28 22 61 70 70 64 61 74 61 22 29 20 26 20 90 02 14 2e 65 78 65 90 00 } //1
		$a_02_2 = {26 20 45 6e 76 69 72 6f 6e 28 22 61 70 70 64 61 74 61 22 29 20 26 20 90 02 14 2e 65 78 65 22 20 26 20 55 73 65 72 46 6f 72 6d 33 2e 52 6f 6f 74 4f 4c 45 32 2e 43 61 70 74 69 6f 6e 90 00 } //1
	condition:
		((#a_00_0  & 1)*5+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=5
 
}