
rule Trojan_Win32_Haorwd_B{
	meta:
		description = "Trojan:Win32/Haorwd.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {8a d0 80 e2 f0 02 d2 02 d2 08 17 8a d0 80 e2 fc c0 e2 04 08 16 c0 e0 06 08 01 c3 } //1
		$a_03_1 = {0f b6 14 06 0f b6 4c 06 90 01 01 88 55 90 01 01 0f b6 54 06 90 01 01 8a 44 06 90 01 01 88 4d 90 01 01 8d 4d 90 01 01 8d 75 90 01 01 8d 7d 90 01 01 88 55 90 01 01 e8 90 01 04 0f b6 4d 90 01 01 8b 45 90 01 01 0f b6 55 90 01 01 88 0c 03 0f b6 4d 90 01 01 43 88 14 03 43 88 0c 03 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}