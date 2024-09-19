
rule Trojan_Win64_Malgentzc_A_MTB{
	meta:
		description = "Trojan:Win64/Malgentzc.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 d2 41 b9 00 30 00 00 41 b8 04 01 00 00 48 8b c8 ff 15 ?? ?? ?? ?? 48 8b e8 4c 8b 4b 10 49 ff c1 4c 8b c3 48 83 7b 18 0f } //1
		$a_02_1 = {48 89 4c 24 20 45 8b ce 41 b8 08 00 00 00 49 8b d4 48 8b 08 ff 15 ?? ?? ?? ?? 41 ff c7 48 83 c7 08 49 63 c7 48 3b c3 41 bc 00 00 00 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}