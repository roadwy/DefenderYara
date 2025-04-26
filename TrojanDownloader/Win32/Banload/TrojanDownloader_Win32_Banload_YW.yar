
rule TrojanDownloader_Win32_Banload_YW{
	meta:
		description = "TrojanDownloader:Win32/Banload.YW,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 "
		
	strings :
		$a_01_0 = {4c 64 72 47 62 70 73 76 } //2 LdrGbpsv
		$a_01_1 = {42 74 6e 53 63 43 6c 69 63 6b } //2 BtnScClick
		$a_01_2 = {50 2e 56 2e 58 2e 34 2e 44 2e 30 2e 52 2e 20 33 2e 34 2e 38 39 } //4 P.V.X.4.D.0.R. 3.4.89
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*4) >=8
 
}