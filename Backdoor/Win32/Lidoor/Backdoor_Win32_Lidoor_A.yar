
rule Backdoor_Win32_Lidoor_A{
	meta:
		description = "Backdoor:Win32/Lidoor.A,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 09 00 07 00 00 02 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 25 73 3a 25 64 2f 50 55 54 5b 25 73 5d 2f 46 43 30 30 31 2f 25 73 } //02 00  http://%s:%d/PUT[%s]/FC001/%s
		$a_00_1 = {6b 69 6c 6c 20 63 6d 64 20 6f 6b } //02 00  kill cmd ok
		$a_00_2 = {68 74 74 70 3a 2f 2f 25 73 3a 25 64 2f 46 43 30 30 31 2f 25 73 } //02 00  http://%s:%d/FC001/%s
		$a_00_3 = {70 61 6e 64 61 6e 6c 69 6e 2e 33 33 32 32 2e 6f 72 67 } //02 00  pandanlin.3322.org
		$a_00_4 = {36 30 2e 32 34 38 2e 37 39 2e 32 32 36 } //01 00  60.248.79.226
		$a_01_5 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //01 00  InternetOpenUrlA
		$a_00_6 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //00 00  URLDownloadToFileA
	condition:
		any of ($a_*)
 
}