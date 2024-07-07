
rule Trojan_Win32_Alureon_FW{
	meta:
		description = "Trojan:Win32/Alureon.FW,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {c0 e8 04 80 e2 0f fe c8 3c 02 77 90 01 01 80 ea 02 80 fa 05 77 04 c6 41 fe 00 41 4e 75 90 01 01 eb 90 01 01 90 03 03 04 39 5d fc 83 7d fc 00 75 90 01 01 83 7d 20 23 72 90 00 } //1
		$a_01_1 = {83 fe 05 72 df 85 f6 75 04 33 c0 eb 3d 8b 45 fc 2b c3 57 83 e8 05 89 45 f5 8b 45 14 8d 3c 1e c6 45 f4 e9 8d 75 f4 } //1
		$a_01_2 = {75 32 83 4a 18 02 8a c8 c0 e9 06 88 4a 0d 8a c8 88 42 0c 0f b6 c0 c0 e9 03 83 e0 07 80 e1 07 43 88 4a 0e 88 42 0f 3c 05 75 0a } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}