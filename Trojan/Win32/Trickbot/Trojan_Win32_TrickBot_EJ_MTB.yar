
rule Trojan_Win32_TrickBot_EJ_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.EJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 c0 2b d0 8b c1 8d 14 51 88 0c 3a 33 d2 f7 f6 a1 ?? ?? ?? ?? 8b e8 0f af e8 a1 ?? ?? ?? ?? 03 c0 2b e8 8b 44 24 10 41 8d 04 68 8a 14 1a 88 54 08 ff a1 ?? ?? ?? ?? 3b c8 72 } //1
		$a_03_1 = {88 04 3a a1 ?? ?? ?? ?? 8d 0c 40 8d 54 09 03 8b 0d ?? ?? ?? ?? 0f af d0 83 c2 03 0f af d0 a1 ?? ?? ?? ?? 03 ea 2b c1 8a 4c 24 1c 8d 04 c0 03 c5 46 88 0c 38 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}