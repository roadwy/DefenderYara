
rule TrojanDownloader_Win32_Graftor_SIBD_MTB{
	meta:
		description = "TrojanDownloader:Win32/Graftor.SIBD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {46 00 61 00 73 00 74 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //1 FastDownloader.exe
		$a_03_1 = {33 d2 89 85 90 01 04 66 a1 90 01 04 66 89 85 90 01 04 a0 90 01 04 88 85 90 01 04 89 95 90 01 04 90 02 0a b8 90 01 04 f7 ea c1 fa 90 01 01 8b c2 c1 e8 90 01 01 03 c2 8b 95 90 1b 05 0f be c0 8a ca 6b c0 90 01 01 2a c8 80 c1 90 01 01 30 8c 15 90 1b 00 42 89 95 90 1b 05 83 fa 90 01 01 7c 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}