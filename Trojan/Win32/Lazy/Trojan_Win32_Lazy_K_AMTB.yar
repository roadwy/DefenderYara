
rule Trojan_Win32_Lazy_K_AMTB{
	meta:
		description = "Trojan:Win32/Lazy.K!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {c1 f9 06 83 e2 3f 6b d2 38 8b 0c 8d 08 51 02 10 88 44 11 29 8b 0b 8b c1 83 e1 3f c1 f8 06 6b f1 38 8b 4d 14 c1 e9 10 8b 14 85 08 51 02 10 32 4c 32 2d 80 e1 01 30 4c 32 2d f6 45 f4 48 75 1f } //5
		$a_80_1 = {73 63 68 74 61 73 6b 73 20 2f 72 75 6e 20 2f 74 6e } //schtasks /run /tn  1
		$a_80_2 = {54 61 73 6b 4d 6f 6e 69 74 6f 72 5f 4d 75 74 65 78 } //TaskMonitor_Mutex  1
	condition:
		((#a_01_0  & 1)*5+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=7
 
}
rule Trojan_Win32_Lazy_K_AMTB_2{
	meta:
		description = "Trojan:Win32/Lazy.K!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {f3 41 0f 6f 00 66 0f 6f ca 0f 57 c8 f3 41 0f 7f 08 f3 41 0f 6f 40 10 66 0f 6f ca 0f 57 c8 f3 41 0f 7f 48 10 f3 41 0f 6f 40 20 66 0f 6f ca 0f 57 c8 f3 41 0f 7f 48 20 f3 41 0f 6f 40 30 66 0f 6f ca 0f 57 c8 f3 41 0f 7f 48 30 49 83 c0 40 48 83 c2 40 48 3b d1 75 a9 } //5
		$a_80_1 = {61 72 69 6f 2e 6b 6f 6c 74 69 67 69 6e 2e 78 79 7a } //ario.koltigin.xyz  1
	condition:
		((#a_01_0  & 1)*5+(#a_80_1  & 1)*1) >=6
 
}