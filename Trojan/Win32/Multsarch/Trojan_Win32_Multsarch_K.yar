
rule Trojan_Win32_Multsarch_K{
	meta:
		description = "Trojan:Win32/Multsarch.K,SIGNATURE_TYPE_PEHSTR,16 00 16 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {46 61 73 74 4d 4d 20 42 6f 72 6c 61 6e 64 20 45 64 69 74 69 6f 6e } //0a 00  FastMM Borland Edition
		$a_01_1 = {57 69 6e 52 41 52 20 32 30 31 } //01 00  WinRAR 201
		$a_01_2 = {3a 2f 2f 73 6d 73 68 65 6c 70 2e 6d 65 2f 3f 61 3d 72 61 74 65 73 26 } //01 00  ://smshelp.me/?a=rates&
		$a_01_3 = {61 72 63 68 69 76 65 2e 65 78 65 } //01 00  archive.exe
		$a_01_4 = {73 74 69 6d 75 90 02 02 6c 70 72 6f 66 90 02 02 69 74 2e 63 6f 6d 2f 90 00 } //01 00 
		$a_01_5 = {3a 00 2f 00 2f 00 73 00 6d 00 73 00 39 00 31 00 } //00 00  ://sms91
	condition:
		any of ($a_*)
 
}