
rule Trojan_Win32_Downloader_CEB_MTB{
	meta:
		description = "Trojan:Win32/Downloader.CEB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {69 11 73 b8 54 e2 3c 00 03 c5 81 c0 86 03 00 00 b9 c1 02 00 00 ba 39 ed 54 1b 30 10 40 49 0f 85 } //01 00 
		$a_00_1 = {bb 0c e2 20 50 98 15 14 f6 db 86 32 fb 49 33 41 76 57 e1 4d } //02 00 
		$a_01_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 57 } //00 00 
	condition:
		any of ($a_*)
 
}