
rule TrojanDownloader_Win32_Banload_KI{
	meta:
		description = "TrojanDownloader:Win32/Banload.KI,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {8a 04 16 3c 2b 72 46 3c 7a 77 42 33 c0 8a c3 80 7c 06 01 2b 72 37 } //5
		$a_01_1 = {ff ff 0d 00 00 00 53 65 75 43 75 7a 61 6f 20 2e } //1
		$a_01_2 = {53 56 43 48 4f 53 54 00 ff ff ff ff 0b 00 00 00 74 61 73 6b 6d 67 72 2e 65 78 65 00 ff ff ff ff } //1
		$a_01_3 = {3a 49 4e 49 43 49 4f } //1 :INICIO
		$a_01_4 = {44 45 4c 41 50 50 20 45 4c 53 45 20 47 4f 54 4f 20 44 45 4c 42 41 54 } //1 DELAPP ELSE GOTO DELBAT
		$a_01_5 = {53 68 61 72 65 64 41 50 50 73 22 3d 2d } //1 SharedAPPs"=-
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=8
 
}