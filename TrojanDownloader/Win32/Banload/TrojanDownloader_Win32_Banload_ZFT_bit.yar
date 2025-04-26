
rule TrojanDownloader_Win32_Banload_ZFT_bit{
	meta:
		description = "TrojanDownloader:Win32/Banload.ZFT!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {32 31 36 2e 32 35 30 2e 39 39 2e 35 2f 74 6f 6e 67 6a 69 2e 70 68 70 3f 75 69 64 3d } //1 216.250.99.5/tongji.php?uid=
		$a_03_1 = {64 6c 2e 65 6e 68 6b 6e 71 71 6c 2e 6c 69 76 65 2f 6d 2f [0-20] 2e 6a 70 67 } //1
		$a_01_2 = {73 79 73 75 70 64 61 74 65 2e 6c 6f 67 } //1 sysupdate.log
		$a_01_3 = {52 75 6e 54 6f 6e 67 4a 69 2e 74 6d 70 } //1 RunTongJi.tmp
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}