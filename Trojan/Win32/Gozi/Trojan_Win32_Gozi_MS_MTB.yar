
rule Trojan_Win32_Gozi_MS_MTB{
	meta:
		description = "Trojan:Win32/Gozi.MS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec 53 57 [0-0a] 8b 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 6a ?? ff 15 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 8b 02 a3 [0-0a] 81 e9 [0-12] 81 c1 ?? ?? ?? ?? a1 ?? ?? ?? ?? a3 } //1
		$a_02_1 = {8b ff 8b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 02 5f 5b 5d c3 } //1
		$a_02_2 = {03 f0 8b 55 ?? 03 32 8b 45 ?? 89 30 8b 4d ?? 8b 11 81 ea ?? ?? ?? ?? 8b 45 ?? 89 10 5e 8b e5 5d c3 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}