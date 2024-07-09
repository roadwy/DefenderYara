
rule TrojanDownloader_Win32_Graftor_SIBD_MTB{
	meta:
		description = "TrojanDownloader:Win32/Graftor.SIBD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {46 00 61 00 73 00 74 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //1 FastDownloader.exe
		$a_03_1 = {33 d2 89 85 ?? ?? ?? ?? 66 a1 ?? ?? ?? ?? 66 89 85 ?? ?? ?? ?? a0 ?? ?? ?? ?? 88 85 ?? ?? ?? ?? 89 95 ?? ?? ?? ?? [0-0a] b8 ?? ?? ?? ?? f7 ea c1 fa ?? 8b c2 c1 e8 ?? 03 c2 8b 95 90 1b 05 0f be c0 8a ca 6b c0 ?? 2a c8 80 c1 ?? 30 8c 15 90 1b 00 42 89 95 90 1b 05 83 fa ?? 7c } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}