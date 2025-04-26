
rule TrojanDownloader_Win32_Banload_BDO{
	meta:
		description = "TrojanDownloader:Win32/Banload.BDO,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 42 33 53 2e 64 61 74 } //1 \B3S.dat
		$a_01_1 = {5c 44 50 52 30 30 39 2e 65 78 65 } //1 \DPR009.exe
		$a_01_2 = {2f 61 63 65 73 73 61 72 2e 70 68 70 } //1 /acessar.php
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}