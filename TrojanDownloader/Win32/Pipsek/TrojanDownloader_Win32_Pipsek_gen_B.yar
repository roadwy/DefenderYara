
rule TrojanDownloader_Win32_Pipsek_gen_B{
	meta:
		description = "TrojanDownloader:Win32/Pipsek.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 79 63 43 74 72 6c 2e 65 78 65 } //1 CycCtrl.exe
		$a_01_1 = {75 73 70 31 30 2e 64 6c 6c } //1 usp10.dll
		$a_01_2 = {6c 71 63 79 63 35 32 2e 63 79 63 } //1 lqcyc52.cyc
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}