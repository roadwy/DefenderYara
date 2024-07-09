
rule Trojan_Win32_Yakes_RL_MTB{
	meta:
		description = "Trojan:Win32/Yakes.RL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b7 ce 8a 14 0a 32 10 46 88 14 39 66 3b 70 ?? 72 90 0a 20 00 8b 50 } //2
		$a_02_1 = {0f 95 c1 57 49 23 c8 03 c8 81 c9 ?? ?? ?? ?? 51 57 57 57 ff 75 ?? 89 4d ?? ff 75 ?? ff 75 ?? ff 15 90 0a 42 00 80 7d ?? ?? b8 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2) >=4
 
}