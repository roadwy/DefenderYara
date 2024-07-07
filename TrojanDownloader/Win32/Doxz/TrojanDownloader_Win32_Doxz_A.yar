
rule TrojanDownloader_Win32_Doxz_A{
	meta:
		description = "TrojanDownloader:Win32/Doxz.A,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0c 00 05 00 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 63 75 70 69 64 2e 35 35 36 36 37 37 38 38 39 39 30 30 2e 63 6f 6d 2f } //1 http://cupid.556677889900.com/
		$a_00_1 = {77 69 6e 64 6f 78 7a } //1 windoxz
		$a_00_2 = {63 75 70 69 64 5f 71 75 69 74 65 76 65 6e 74 } //1 cupid_quitevent
		$a_00_3 = {53 6f 66 74 77 61 72 65 5c 63 75 70 69 64 } //1 Software\cupid
		$a_01_4 = {2e 70 68 70 3f 61 66 66 5f 69 64 3d 25 41 46 46 49 44 26 6c 75 6e 63 68 5f 69 64 3d 25 4c 55 4e 43 48 49 44 } //10 .php?aff_id=%AFFID&lunch_id=%LUNCHID
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*10) >=12
 
}