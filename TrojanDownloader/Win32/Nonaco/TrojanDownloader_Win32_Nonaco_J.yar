
rule TrojanDownloader_Win32_Nonaco_J{
	meta:
		description = "TrojanDownloader:Win32/Nonaco.J,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_03_0 = {8b c1 8b f7 8b fa c6 44 24 90 01 01 75 c1 e9 02 c6 44 24 90 01 01 72 c6 44 24 90 01 01 6c c6 44 24 90 01 01 63 90 00 } //3
		$a_01_1 = {f7 fb 8b 45 10 32 11 46 3b 75 0c 88 54 30 fe 7c e1 } //2
		$a_01_2 = {49 6e 76 6f 6b 65 20 64 69 73 70 69 64 20 3d 20 25 64 } //1 Invoke dispid = %d
		$a_01_3 = {67 67 67 67 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 } //1
		$a_01_4 = {6d 61 69 6e 66 65 65 64 74 68 65 72 65 2e 63 6f 6d } //1 mainfeedthere.com
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}