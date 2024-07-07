
rule TrojanDownloader_Win32_Rescoms_B{
	meta:
		description = "TrojanDownloader:Win32/Rescoms.B,SIGNATURE_TYPE_PEHSTR,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 75 00 6e 00 69 00 66 00 73 00 63 00 6f 00 6e 00 2e 00 63 00 6f 00 6d 00 2f 00 52 00 65 00 6d 00 41 00 70 00 2e 00 65 00 78 00 65 00 } //3 http://unifscon.com/RemAp.exe
		$a_01_1 = {75 72 6c 64 6f 77 6e 6c 6f 61 64 74 6f 66 69 6c 65 77 } //1 urldownloadtofilew
		$a_01_2 = {73 68 65 6c 6c 65 78 65 63 75 74 65 77 } //1 shellexecutew
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}