
rule TrojanDownloader_Win32_Dogkild_D{
	meta:
		description = "TrojanDownloader:Win32/Dogkild.D,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4f 70 65 6e 53 43 4d 61 6e 61 67 65 72 41 } //1 OpenSCManagerA
		$a_00_1 = {70 63 69 64 75 6d 70 00 5c 5c 2e 5c 70 63 69 64 75 6d 70 } //1
		$a_01_2 = {43 4f 4d 53 50 45 43 00 73 63 76 68 6f 73 74 2e 65 78 65 } //1
		$a_01_3 = {53 45 52 56 45 52 00 00 5c 6b 69 6c 6c 64 6c 6c 2e 64 6c 6c } //1
		$a_00_4 = {e9 01 00 00 00 e8 b8 11 06 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}