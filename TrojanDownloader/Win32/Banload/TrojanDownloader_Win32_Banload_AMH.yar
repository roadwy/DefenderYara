
rule TrojanDownloader_Win32_Banload_AMH{
	meta:
		description = "TrojanDownloader:Win32/Banload.AMH,SIGNATURE_TYPE_PEHSTR,10 00 10 00 06 00 00 05 00 "
		
	strings :
		$a_01_0 = {24 67 63 61 70 74 } //05 00  $gcapt
		$a_01_1 = {73 76 63 68 6f 73 3a } //05 00  svchos:
		$a_01_2 = {7b 30 35 44 43 44 37 42 35 2d 35 33 46 46 2d 34 64 33 61 2d 39 31 41 38 2d 32 37 42 34 42 42 34 36 33 34 33 36 7d } //02 00  {05DCD7B5-53FF-4d3a-91A8-27B4BB463436}
		$a_01_3 = {2e 62 62 2e 63 6f 6d 2e 62 72 2f 61 61 70 6a 2f 6c 6f 67 69 6e 6d 70 65 2e 62 62 } //02 00  .bb.com.br/aapj/loginmpe.bb
		$a_01_4 = {2e 62 62 2e 63 6f 6d 2e 62 72 2f 61 61 70 6a 2f 6c 6f 67 69 6e 70 66 65 2e 62 62 } //02 00  .bb.com.br/aapj/loginpfe.bb
		$a_01_5 = {5c 42 61 42 79 5c 44 65 73 6b 74 6f 70 5c 50 45 4e 5c 52 6f 74 69 6e 61 73 20 55 74 65 69 73 5c 4e 4f 56 4f 20 42 48 4f 20 2d 20 54 4e 54 20 2d 20 43 41 50 54 48 41 5c } //00 00  \BaBy\Desktop\PEN\Rotinas Uteis\NOVO BHO - TNT - CAPTHA\
	condition:
		any of ($a_*)
 
}