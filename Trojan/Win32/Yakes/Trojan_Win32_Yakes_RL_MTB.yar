
rule Trojan_Win32_Yakes_RL_MTB{
	meta:
		description = "Trojan:Win32/Yakes.RL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b7 ce 8a 14 0a 32 10 46 88 14 39 66 3b 70 90 01 01 72 90 0a 20 00 8b 50 90 00 } //2
		$a_02_1 = {0f 95 c1 57 49 23 c8 03 c8 81 c9 90 01 04 51 57 57 57 ff 75 90 01 01 89 4d 90 01 01 ff 75 90 01 01 ff 75 90 01 01 ff 15 90 0a 42 00 80 7d 90 01 02 b8 90 00 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2) >=4
 
}