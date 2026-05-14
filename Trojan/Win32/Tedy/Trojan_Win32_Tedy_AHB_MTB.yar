
rule Trojan_Win32_Tedy_AHB_MTB{
	meta:
		description = "Trojan:Win32/Tedy.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b d0 8b 44 24 04 03 d1 80 c2 ?? 88 94 04 07 06 00 00 8b 44 24 04 40 89 44 24 04 83 7c 24 04 ?? 72 } //20
		$a_01_1 = {c7 84 24 44 05 00 00 34 3f 33 3a 66 c7 84 24 48 05 00 00 2a a5 0f 11 84 24 4a 05 00 00 c7 44 24 04 00 00 00 00 } //30
	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*30) >=50
 
}