
rule TrojanDownloader_Win32_WinShow_gen_H{
	meta:
		description = "TrojanDownloader:Win32/WinShow.gen!H,SIGNATURE_TYPE_PEHSTR,02 00 02 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {00 46 65 61 74 32 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00  䘀慥㉴䐮䱌䐀汬慃啮汮慯乤睯䐀汬敇䍴慬獳扏敪瑣䐀汬敒楧瑳牥敓癲牥
		$a_01_1 = {46 65 61 74 32 20 55 70 64 61 74 65 72 20 34 37 00 } //01 00 
		$a_01_2 = {00 46 65 61 74 32 43 6f 6e 66 69 67 4d 65 6d 6f 72 79 } //00 00  䘀慥㉴潃普杩敍潭祲
	condition:
		any of ($a_*)
 
}