
rule TrojanDownloader_Win32_Banload_KK{
	meta:
		description = "TrojanDownloader:Win32/Banload.KK,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {26 70 69 3d 4c 4f 41 44 5f } //1 &pi=LOAD_
		$a_01_1 = {61 74 74 72 69 62 20 2b 52 20 2d 41 20 2b 53 20 2b 48 } //1 attrib +R -A +S +H
		$a_01_2 = {20 7c 20 66 69 6e 64 20 22 20 30 20 62 79 74 65 73 22 20 3e 20 4e 55 4c } //1  | find " 0 bytes" > NUL
		$a_01_3 = {67 6f 74 6f 20 66 69 6e 61 6c 69 7a 61 72 } //1 goto finalizar
		$a_01_4 = {43 3a 5c 70 61 67 65 66 69 6c 65 2e 6c 6f 67 } //1 C:\pagefile.log
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}