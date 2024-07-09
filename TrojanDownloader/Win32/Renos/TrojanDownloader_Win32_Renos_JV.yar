
rule TrojanDownloader_Win32_Renos_JV{
	meta:
		description = "TrojanDownloader:Win32/Renos.JV,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_03_0 = {68 00 14 2d 00 90 09 03 00 6a (0c|90) 04 01 03 50 2d 57 18 } //1
		$a_03_1 = {40 3d 00 01 00 00 ?? (f1|f4) } //1
		$a_01_2 = {66 81 3e 8b ff 75 2e 80 3f 90 75 29 } //1
		$a_01_3 = {c6 04 03 b8 43 89 14 03 83 c3 04 8d 51 04 c6 04 03 ff 43 c6 04 03 d0 } //1
		$a_01_4 = {44 6c 6c 44 65 66 69 6e 65 00 44 6c 6c 52 65 67 } //1 汄䑬晥湩e汄剬来
		$a_01_5 = {3c 2f 75 72 6c 3e 3c 2f 63 6f 6e 66 69 67 3e } //1 </url></config>
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=3
 
}