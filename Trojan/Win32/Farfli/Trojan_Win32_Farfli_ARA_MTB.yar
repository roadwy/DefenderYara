
rule Trojan_Win32_Farfli_ARA_MTB{
	meta:
		description = "Trojan:Win32/Farfli.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 7d 08 b8 ?? ?? ?? ?? 80 c2 3d 30 14 31 8b ce f7 e6 c1 ea 03 8d 04 92 03 c0 2b c8 f7 d9 1b c9 46 23 d9 3b f7 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Farfli_ARA_MTB_2{
	meta:
		description = "Trojan:Win32/Farfli.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {83 f2 58 8b 45 08 03 45 e8 88 10 eb d8 } //2
		$a_01_1 = {8b 45 08 03 c1 80 30 58 41 3b 4d 0c 7c f2 } //2
		$a_01_2 = {8b 45 10 8a 04 02 30 01 46 eb e0 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=2
 
}