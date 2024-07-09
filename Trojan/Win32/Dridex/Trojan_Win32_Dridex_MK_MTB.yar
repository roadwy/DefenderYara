
rule Trojan_Win32_Dridex_MK_MTB{
	meta:
		description = "Trojan:Win32/Dridex.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_00_0 = {3d 12 35 09 00 77 07 cc cc cc 40 cc eb f2 } //10
		$a_03_1 = {77 07 cc cc cc 40 cc eb f2 90 09 05 00 3d ?? ?? ?? 00 } //10
	condition:
		((#a_00_0  & 1)*10+(#a_03_1  & 1)*10) >=10
 
}
rule Trojan_Win32_Dridex_MK_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 04 16 8d 7c 07 be 8d 0c 3f 8b c1 2b c6 0f af c5 69 c0 ?? ?? ?? ?? 4b 2b c8 8d bc 31 ?? ?? ?? ?? 85 db 75 d5 } //1
		$a_03_1 = {8b 0d 9c cc 44 00 0f b7 05 ?? ?? ?? ?? 6b c9 ?? 03 c8 8d 14 09 b8 ?? ?? ?? ?? 2b c2 0f b7 c0 89 0d ?? ?? ?? ?? 8d 4c 08 bf 89 0d ?? ?? ?? ?? c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Dridex_MK_MTB_3{
	meta:
		description = "Trojan:Win32/Dridex.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 eb 01 03 f3 8d 7c 37 ec 8d 77 e7 8b c6 6b c0 ?? 2b c5 01 05 ?? ?? ?? ?? 85 db 75 e3 } //1
		$a_03_1 = {0f b7 cb 8d 5c 02 ?? 8b c2 6b c0 ?? 8d 6c 29 c9 8b 0e 81 c1 ?? ?? ?? ?? 89 0e 2b c5 83 c6 ?? 83 6c 24 10 ?? 89 2d ?? ?? ?? ?? 8d 44 38 da 75 99 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}