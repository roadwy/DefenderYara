
rule Trojan_Win32_Zlob_gen_P{
	meta:
		description = "Trojan:Win32/Zlob.gen!P,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {c1 e2 04 0f b7 45 ?? 03 d0 66 89 55 ?? eb } //1
		$a_03_1 = {eb 09 8b 4d ?? 83 c1 01 89 4d ?? 8b 55 ?? 3b 55 ?? 73 ?? 8b 45 0c 03 45 ?? 66 0f be 08 66 89 4d ?? 0f b7 55 ?? 81 f2 ?? ?? 00 00 52 8d 45 ?? 50 e8 ?? ?? ff ff 83 c4 08 } //1
		$a_03_2 = {73 5b 8b 4d ec 51 8b 4d 0c e8 ?? ?? 00 00 8b c8 e8 ?? ?? ff ff 50 68 ?? ?? ?? 00 8d 55 b4 52 e8 ?? ?? ff ff 83 c4 08 89 45 a8 8b 45 a8 89 45 a4 c7 45 fc 01 00 00 00 8b 4d a4 } //1
		$a_03_3 = {eb 09 8b 55 ?? 83 c2 01 89 55 ?? 8b 45 ?? 3b 45 ?? 73 2e 8b 4d 0c 51 e8 ?? ?? ff ff 83 c4 04 66 89 45 ?? 0f b7 55 ?? 81 f2 ?? ?? 00 00 52 8d 4d ?? e8 ?? ?? 00 00 8b 45 0c 83 c0 ?? 89 45 0c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}