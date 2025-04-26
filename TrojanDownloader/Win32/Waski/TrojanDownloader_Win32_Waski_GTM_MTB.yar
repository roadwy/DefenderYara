
rule TrojanDownloader_Win32_Waski_GTM_MTB{
	meta:
		description = "TrojanDownloader:Win32/Waski.GTM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 10 8b 14 85 10 30 40 00 33 c0 8b cf 40 c1 e9 02 3b c8 76 08 31 14 83 40 3b c1 72 f8 } //10
		$a_80_1 = {2f 6c 6f 6f 6b 73 2f 37 37 37 5f 32 33 30 35 55 53 6d 77 5f 31 2e 7a 69 70 } ///looks/777_2305USmw_1.zip  1
		$a_80_2 = {72 73 65 6f 6d 61 74 2e 65 78 65 } //rseomat.exe  1
	condition:
		((#a_01_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=12
 
}