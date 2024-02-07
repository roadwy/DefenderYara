
rule Trojan_Win32_Injector_ARA_MTB{
	meta:
		description = "Trojan:Win32/Injector.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b c7 99 f7 7d 10 8b 45 0c 47 3b fe 8a 04 02 88 84 3d ff fe ff ff 7c e8 } //01 00 
		$a_01_1 = {8b 45 0c 8a 19 0f b6 14 08 0f b6 c3 03 fa 03 c7 8b fe 99 f7 ff 8b 45 08 8b fa 8a 14 38 03 c7 88 11 41 ff 4d 10 88 18 75 d7 5f } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Injector_ARA_MTB_2{
	meta:
		description = "Trojan:Win32/Injector.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 7a 79 2e 6c 6f 67 } //02 00  C:\Users\Public\Documents\zy.log
		$a_01_1 = {73 6f 66 74 77 61 72 65 5c 57 4f 57 36 34 33 32 4e 6f 64 65 5c 54 65 6e 63 65 6e 74 5c 51 51 32 30 30 39 5c 49 6e 73 74 61 6c 6c } //02 00  software\WOW6432Node\Tencent\QQ2009\Install
		$a_01_2 = {48 69 70 73 54 72 61 79 2e 65 78 65 } //02 00  HipsTray.exe
		$a_01_3 = {33 36 30 74 72 61 79 2e 65 78 65 } //02 00  360tray.exe
		$a_01_4 = {56 40 5c 62 68 64 6c 6c 2e 64 61 74 } //02 00  V@\bhdll.dat
		$a_01_5 = {66 75 63 6b 79 6f 75 32 } //00 00  fuckyou2
	condition:
		any of ($a_*)
 
}