
rule TrojanDownloader_Win32_Lwsta{
	meta:
		description = "TrojanDownloader:Win32/Lwsta,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {00 61 70 6a 61 63 6b 00 } //1 愀橰捡k
		$a_00_1 = {70 70 63 62 6f 6f 73 74 65 72 00 70 70 63 62 6f 6f 73 74 65 72 00 00 50 72 6f 6a 65 63 74 31 } //1
		$a_00_2 = {2e 00 61 00 70 00 61 00 72 00 74 00 6d 00 65 00 6e 00 74 00 6a 00 61 00 63 00 6b 00 70 00 6f 00 74 00 2e 00 63 00 6f 00 6d 00 } //1 .apartmentjackpot.com
		$a_00_3 = {6c 00 77 00 73 00 74 00 61 00 74 00 73 00 2e 00 63 00 6f 00 6d 00 2f 00 70 00 70 00 63 00 62 00 70 00 6f 00 70 00 } //1 lwstats.com/ppcbpop
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}