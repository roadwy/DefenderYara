
rule TrojanDownloader_Win32_Mukeralmoh_STC{
	meta:
		description = "TrojanDownloader:Win32/Mukeralmoh.STC,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {78 6c 41 75 74 6f 4f 70 65 6e 00 } //2
		$a_01_1 = {73 00 72 00 61 00 6e 00 64 00 30 00 34 00 72 00 66 00 2e 00 72 00 75 00 } //1 srand04rf.ru
		$a_01_2 = {25 00 50 00 55 00 42 00 4c 00 49 00 43 00 25 00 5c 00 72 00 65 00 73 00 33 00 32 00 2e 00 68 00 74 00 61 00 } //1 %PUBLIC%\res32.hta
		$a_01_3 = {2f 00 39 00 32 00 33 00 37 00 35 00 32 00 33 00 34 00 2e 00 78 00 6d 00 6c 00 } //1 /92375234.xml
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}