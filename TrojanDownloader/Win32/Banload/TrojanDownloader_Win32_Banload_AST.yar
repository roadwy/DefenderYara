
rule TrojanDownloader_Win32_Banload_AST{
	meta:
		description = "TrojanDownloader:Win32/Banload.AST,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_03_0 = {0f bf c7 52 8b 11 50 52 c7 45 90 01 01 01 00 00 00 c7 45 90 01 01 02 00 00 00 ff 15 90 01 04 8b d0 8d 4d 90 00 } //2
		$a_01_1 = {50 72 6f 6a 65 63 74 31 2e 56 62 44 4c } //3 Project1.VbDL
		$a_01_2 = {6b 72 61 69 32 } //3 krai2
		$a_01_3 = {63 00 3a 00 5c 00 61 00 73 00 64 00 66 00 5c 00 73 00 64 00 66 00 2e 00 65 00 78 00 65 00 00 00 } //4
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*4) >=12
 
}