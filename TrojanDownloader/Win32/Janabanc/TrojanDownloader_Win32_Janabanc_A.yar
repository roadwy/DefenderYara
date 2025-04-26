
rule TrojanDownloader_Win32_Janabanc_A{
	meta:
		description = "TrojanDownloader:Win32/Janabanc.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {54 00 45 00 4d 00 50 00 5c 00 70 00 57 00 6d 00 6c 00 6e 00 6e 00 6f 00 73 00 6f 00 6e 00 2e 00 65 00 78 00 65 00 } //1 TEMP\pWmlnnoson.exe
		$a_01_1 = {38 47 46 46 34 58 4c 42 37 57 48 4d 37 58 37 58 4b 4c 4a 33 51 45 59 4e 4c 47 42 54 34 41 46 32 48 4c 37 42 39 48 } //1 8GFF4XLB7WHM7X7XKLJ3QEYNLGBT4AF2HL7B9H
		$a_01_2 = {4a 61 6e 65 6c 61 73 64 6f 57 4e } //1 JanelasdoWN
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}