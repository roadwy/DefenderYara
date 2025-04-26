
rule TrojanDownloader_Win64_DCRat_D_MTB{
	meta:
		description = "TrojanDownloader:Win64/DCRat.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {3a 00 2f 00 2f 00 79 00 61 00 79 00 73 00 65 00 6d 00 2e 00 72 00 75 00 2e 00 73 00 77 00 74 00 65 00 73 00 74 00 2e 00 72 00 75 00 2f 00 66 00 61 00 2e 00 65 00 78 00 65 00 } //2 ://yaysem.ru.swtest.ru/fa.exe
		$a_01_1 = {74 00 65 00 73 00 74 00 2e 00 65 00 78 00 65 00 } //2 test.exe
		$a_01_2 = {6f 00 70 00 65 00 6e 00 } //2 open
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}