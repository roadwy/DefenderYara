
rule TrojanDownloader_Win32_Donloblib_EM_MTB{
	meta:
		description = "TrojanDownloader:Win32/Donloblib.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 04 00 00 "
		
	strings :
		$a_01_0 = {8d 4d f0 c7 45 f0 00 00 00 00 51 68 00 04 00 00 8d 8d dc fb ff ff 51 50 } //5
		$a_01_1 = {32 31 32 2e 34 36 2e 33 38 2e 32 33 38 2f 75 70 64 2e 70 68 70 } //10 212.46.38.238/upd.php
		$a_01_2 = {31 36 32 2e 31 39 2e 32 31 34 2e 32 30 38 2f 75 70 64 2e 70 68 70 } //10 162.19.214.208/upd.php
		$a_01_3 = {31 39 33 2e 32 34 33 2e 31 34 37 2e 31 34 33 2f 75 70 64 2e 70 68 70 } //10 193.243.147.143/upd.php
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10) >=15
 
}