
rule TrojanDownloader_Win32_Banload_AJV{
	meta:
		description = "TrojanDownloader:Win32/Banload.AJV,SIGNATURE_TYPE_PEHSTR_EXT,12 00 0e 00 05 00 00 "
		
	strings :
		$a_01_0 = {4b 63 4c 64 53 74 50 6f 43 70 38 57 42 72 43 57 4e 35 6d 6e 43 5a 53 6b 43 32 75 6d 42 5a 35 53 47 4d 48 6a 51 4d 75 61 4e 36 39 6f 4f 4d 48 58 42 63 48 69 52 30 } //10 KcLdStPoCp8WBrCWN5mnCZSkC2umBZ5SGMHjQMuaN69oOMHXBcHiR0
		$a_00_1 = {62 62 2d 67 65 72 65 6e 63 69 61 64 6f 72 66 69 6e 61 6e 63 65 69 72 6f 2e 63 6f 6d 2f 66 69 6c 65 73 } //8 bb-gerenciadorfinanceiro.com/files
		$a_00_2 = {44 6f 77 6e 6c 6f 61 64 73 5c 62 72 61 64 61 37 2e 65 78 65 } //4 Downloads\brada7.exe
		$a_00_3 = {50 75 62 6c 69 63 5c 44 6f 77 6e 6c 6f 61 64 73 5c 69 6e 73 74 61 6e 74 2e 65 78 65 } //4 Public\Downloads\instant.exe
		$a_00_4 = {62 72 61 64 61 2e 64 6c 6c } //4 brada.dll
	condition:
		((#a_01_0  & 1)*10+(#a_00_1  & 1)*8+(#a_00_2  & 1)*4+(#a_00_3  & 1)*4+(#a_00_4  & 1)*4) >=14
 
}