
rule TrojanDownloader_Win32_Pacerd{
	meta:
		description = "TrojanDownloader:Win32/Pacerd,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 74 65 72 6d 73 2f 70 74 66 5f } //3 /terms/ptf_
		$a_01_1 = {49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 20 36 2e 30 41 44 31 } //1 Internet Explorer 6.0AD1
		$a_01_2 = {2e 70 61 63 69 6d 65 64 69 61 2e 63 6f 6d } //3 .pacimedia.com
		$a_01_3 = {50 72 6f 6a 65 63 74 73 5c 70 61 63 65 72 64 5c 73 74 75 62 5c } //3 Projects\pacerd\stub\
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3) >=10
 
}