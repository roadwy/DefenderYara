
rule TrojanDownloader_Win32_Adload_BM_dll{
	meta:
		description = "TrojanDownloader:Win32/Adload.BM!dll,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {26 75 5f 68 69 73 3d 31 26 75 5f 6a 61 76 61 3d 74 72 75 65 26 75 5f 6e 70 6c 75 67 3d 30 26 75 5f 6e 6d 69 6d 65 3d 30 26 66 72 6d 3d 30 } //1 &u_his=1&u_java=true&u_nplug=0&u_nmime=0&frm=0
		$a_01_1 = {25 73 5c 61 62 25 64 25 64 25 64 2e 74 6d 70 } //1 %s\ab%d%d%d.tmp
		$a_01_2 = {25 73 5c 31 30 32 38 5c 69 65 76 65 72 73 69 6f 6e 2e 69 6e 69 } //1 %s\1028\ieversion.ini
		$a_03_3 = {68 10 27 00 00 ff ?? a1 ?? ?? ?? ?? 83 f8 03 74 05 83 f8 01 75 ea } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}