
rule Trojan_Win32_ClipBanker_AMAA_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.AMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {28 5e 7c 5c 73 29 5b 31 33 5d 7b 31 7d 5b 61 2d 6b 6d 2d 7a 41 2d 48 4a 2d 4e 50 2d 5a 31 2d 39 5d 7b 32 35 2c 33 34 7d 28 24 7c 5c 73 29 } //01 00 
		$a_01_1 = {7c 5c 73 29 62 6e 62 5b 61 2d 7a 41 2d 5a 30 2d 39 5d 7b 33 38 2c 34 30 7d 28 24 7c 5c 73 29 } //01 00 
		$a_80_2 = {42 74 63 42 75 66 52 5f 49 6e 73 74 61 6e 63 65 } //BtcBufR_Instance  01 00 
		$a_80_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 4f 6e 63 65 } //Software\Microsoft\Windows\CurrentVersion\RunOnce  01 00 
		$a_80_4 = {47 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //GetClipboardData  01 00 
		$a_80_5 = {53 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //SetClipboardData  00 00 
	condition:
		any of ($a_*)
 
}