
rule TrojanDownloader_Win32_Delf_ZWH{
	meta:
		description = "TrojanDownloader:Win32/Delf.ZWH,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 00 65 00 78 00 65 00 2e 00 65 00 78 00 65 00 } //1 \exe.exe
		$a_01_1 = {63 00 3a 00 5c 00 72 00 65 00 73 00 75 00 6c 00 74 00 2e 00 76 00 62 00 73 00 } //1 c:\result.vbs
		$a_01_2 = {63 20 3a 20 5c 20 65 20 78 20 65 20 2e 20 65 20 78 20 65 } //1 c : \ e x e . e x e
		$a_01_3 = {2f 20 64 20 6c 20 2e 20 64 20 72 20 6f 20 70 20 62 20 6f 20 78 20 2e 20 63 20 6f 20 6d 20 2f 20 75 20 2f 20 32 20 30 20 32 20 30 20 36 20 32 20 30 20 2f 20 66 20 69 20 6e 20 65 20 70 20 72 20 6f 20 78 20 79 20 2e 20 65 20 78 20 65 } //1 / d l . d r o p b o x . c o m / u / 2 0 2 0 6 2 0 / f i n e p r o x y . e x e
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}