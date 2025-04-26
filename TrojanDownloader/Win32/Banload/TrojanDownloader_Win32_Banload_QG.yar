
rule TrojanDownloader_Win32_Banload_QG{
	meta:
		description = "TrojanDownloader:Win32/Banload.QG,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {63 6d 64 20 2f 6b 20 43 3a 5c 74 65 6d 70 5c 69 6d 67 ?? 2e 65 78 65 } //3
		$a_00_1 = {2f 00 69 00 6d 00 61 00 67 00 65 00 73 00 2f 00 66 00 6f 00 6c 00 6c 00 65 00 2f 00 62 00 62 00 2e 00 74 00 78 00 74 00 } //1 /images/folle/bb.txt
		$a_00_2 = {2f 00 69 00 6d 00 61 00 67 00 65 00 73 00 2f 00 66 00 6f 00 6c 00 6c 00 65 00 2f 00 64 00 65 00 63 00 6f 00 2e 00 74 00 78 00 74 00 } //1 /images/folle/deco.txt
		$a_00_3 = {2f 00 69 00 6d 00 61 00 67 00 65 00 73 00 2f 00 66 00 6f 00 6c 00 6c 00 65 00 2f 00 63 00 66 00 2e 00 74 00 78 00 74 00 } //1 /images/folle/cf.txt
	condition:
		((#a_03_0  & 1)*3+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}