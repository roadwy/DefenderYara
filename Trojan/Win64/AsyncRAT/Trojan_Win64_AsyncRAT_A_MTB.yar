
rule Trojan_Win64_AsyncRAT_A_MTB{
	meta:
		description = "Trojan:Win64/AsyncRAT.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 04 01 48 89 84 24 ?? ?? ?? ?? 48 63 4c 24 ?? 33 d2 48 8b c1 b9 ?? ?? ?? ?? 48 f7 f1 48 8b c2 48 0f be 84 04 ?? ?? ?? ?? 48 89 84 24 ?? ?? ?? ?? 48 8d 8c 24 } //2
		$a_03_1 = {48 8b 8c 24 ?? ?? ?? ?? 48 03 c8 48 8b c1 48 8b 8c 24 ?? ?? ?? ?? 48 33 c8 48 8b c1 48 63 4c 24 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}