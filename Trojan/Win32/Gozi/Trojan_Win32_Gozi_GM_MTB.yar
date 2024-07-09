
rule Trojan_Win32_Gozi_GM_MTB{
	meta:
		description = "Trojan:Win32/Gozi.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {66 2b d0 0f b7 c2 8b 55 ?? 89 45 ?? 0f b7 75 ?? 8d 42 ?? 02 c8 8d 04 b7 88 0d ?? ?? ?? ?? 03 c6 a3 ?? ?? ?? ?? 0f b6 c1 2b c2 83 c0 ?? 89 45 ?? ff 15 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Gozi_GM_MTB_2{
	meta:
		description = "Trojan:Win32/Gozi.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {83 c4 08 8b 55 f0 8b 45 fc 8d 8c 10 ?? ?? ?? ?? 89 4d ?? 8b 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 8b 45 ?? a3 ?? ?? ?? ?? 8b 4d ?? 83 c1 ?? 89 4d } //1
		$a_02_1 = {83 e9 21 89 0d ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 83 c1 ?? a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? b8 ?? ?? ?? ?? b8 ?? ?? ?? ?? a1 [0-c8] 31 0d } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Gozi_GM_MTB_3{
	meta:
		description = "Trojan:Win32/Gozi.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 45 ef 83 e8 ?? 99 03 05 [0-04] 13 15 [0-04] a2 [0-04] 0f b7 05 [0-04] 3d [0-04] 90 18 0f b6 45 ?? 83 e8 ?? 99 03 45 ?? 13 55 ?? a3 [0-04] 89 15 [0-04] a1 [0-04] 05 [0-04] a3 [0-04] 8b 0d [0-04] 03 4d ?? 8b 15 [0-04] 89 91 [0-04] a1 [0-04] 83 e8 ?? 33 c9 2b 05 [0-04] 1b 0d [0-04] 88 45 ?? e9 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}