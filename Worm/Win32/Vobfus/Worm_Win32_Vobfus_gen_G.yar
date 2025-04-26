
rule Worm_Win32_Vobfus_gen_G{
	meta:
		description = "Worm:Win32/Vobfus.gen!G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {5f 5f 76 62 61 56 61 72 54 73 74 45 71 [0-04] 5f 5f 76 62 61 47 65 6e 65 72 61 74 65 42 6f 75 6e 64 73 45 72 72 6f 72 00 } //1
		$a_03_1 = {73 0c c7 85 90 09 1e 00 c7 85 ?? ?? ff ff ?? ?? ?? ?? c7 85 ?? ?? ff ff ?? ?? ?? ?? 81 bd 90 1b 03 ff ff ?? ?? ?? ?? 73 0c c7 85 ?? ?? ff ff 00 00 00 00 eb 0c ff 15 ?? ?? ?? ?? 89 85 ?? ?? ff ff 8d 95 90 1b 01 ff ff 8b 8d 90 1b 03 ff ff } //1
		$a_03_2 = {c1 e1 04 8b 15 ?? ?? ?? ?? 03 d1 8b 85 ?? ?? ff ff c1 e0 04 8b 0d ?? ?? ?? ?? 03 c8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}