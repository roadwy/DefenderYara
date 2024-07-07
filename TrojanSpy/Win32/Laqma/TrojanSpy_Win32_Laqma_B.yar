
rule TrojanSpy_Win32_Laqma_B{
	meta:
		description = "TrojanSpy:Win32/Laqma.B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {83 7d 0c 10 75 1f 81 7d 10 32 02 00 00 75 16 81 7d 14 65 a3 00 00 75 0d e8 90 01 02 00 00 6a 00 ff 15 90 00 } //1
		$a_00_1 = {ff d3 80 3e 21 75 37 80 7e 01 45 75 31 80 7e 02 58 75 2b 80 7e 03 21 75 25 51 8d 46 04 8b cc 50 e8 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}