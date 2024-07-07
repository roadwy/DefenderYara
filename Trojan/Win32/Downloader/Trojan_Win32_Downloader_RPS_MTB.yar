
rule Trojan_Win32_Downloader_RPS_MTB{
	meta:
		description = "Trojan:Win32/Downloader.RPS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c7 44 24 60 0e e3 4f 55 8d 44 24 60 c7 44 24 64 3c 2d 92 b8 c7 44 24 68 a8 05 37 ba c7 44 24 6c 6a 12 38 e0 0f 28 4c 24 60 68 90 01 04 c7 44 24 54 65 86 3d 3b c7 44 24 58 59 41 a1 8a c7 44 24 5c 86 61 5b d6 c7 44 24 60 6a 12 38 e0 66 0f ef 4c 24 54 50 6a 00 0f 29 4c 24 6c ff 15 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}