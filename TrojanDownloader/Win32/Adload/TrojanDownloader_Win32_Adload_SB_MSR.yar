
rule TrojanDownloader_Win32_Adload_SB_MSR{
	meta:
		description = "TrojanDownloader:Win32/Adload.SB!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 65 6c 65 61 73 65 5c 61 64 76 69 73 65 72 2e 70 64 62 } //1 Release\adviser.pdb
		$a_01_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 79 00 61 00 73 00 6f 00 76 00 65 00 74 00 6e 00 31 00 6b 00 2e 00 72 00 75 00 2f 00 66 00 69 00 6c 00 65 00 73 00 2f 00 } //2 http://yasovetn1k.ru/files/
		$a_01_2 = {70 00 61 00 79 00 6f 00 75 00 74 00 } //1 payout
		$a_01_3 = {74 65 6d 70 5f 64 69 72 65 63 74 6f 72 79 5f 70 61 74 68 28 29 } //1 temp_directory_path()
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}