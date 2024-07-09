
rule Trojan_Win32_Haorwd_B{
	meta:
		description = "Trojan:Win32/Haorwd.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {8a d0 80 e2 f0 02 d2 02 d2 08 17 8a d0 80 e2 fc c0 e2 04 08 16 c0 e0 06 08 01 c3 } //1
		$a_03_1 = {0f b6 14 06 0f b6 4c 06 ?? 88 55 ?? 0f b6 54 06 ?? 8a 44 06 ?? 88 4d ?? 8d 4d ?? 8d 75 ?? 8d 7d ?? 88 55 ?? e8 ?? ?? ?? ?? 0f b6 4d ?? 8b 45 ?? 0f b6 55 ?? 88 0c 03 0f b6 4d ?? 43 88 14 03 43 88 0c 03 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}