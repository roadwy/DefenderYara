
rule TrojanSpy_Win32_Banker_RB{
	meta:
		description = "TrojanSpy:Win32/Banker.RB,SIGNATURE_TYPE_PEHSTR_EXT,2c 01 2c 01 03 00 00 "
		
	strings :
		$a_01_0 = {73 64 66 6a 6e 6c 64 66 6b 67 6e 64 73 } //100 sdfjnldfkgnds
		$a_01_1 = {64 00 66 00 67 00 64 00 66 00 67 00 64 00 66 00 67 00 2e 00 65 00 78 00 65 00 } //100 dfgdfgdfg.exe
		$a_01_2 = {64 66 3b 6d 67 73 64 66 6f 6e 67 73 6f 64 66 6e 67 6f 6c 73 6e 66 64 6b 67 6f 6c 73 64 6e 66 67 6f 73 62 66 64 6f 67 6a 73 6e } //100 df;mgsdfongsodfngolsnfdkgolsdnfgosbfdogjsn
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*100+(#a_01_2  & 1)*100) >=300
 
}