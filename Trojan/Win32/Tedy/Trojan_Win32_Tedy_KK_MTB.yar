
rule Trojan_Win32_Tedy_KK_MTB{
	meta:
		description = "Trojan:Win32/Tedy.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 44 1d 00 04 0b 30 04 0e 89 c8 ba cd cc cc cc f7 e2 c1 ea 02 83 e2 fe 8d 04 92 43 39 c8 b8 00 00 00 00 0f 44 d8 41 39 cf } //20
		$a_03_1 = {0f b6 04 1f 04 [0-06] 30 04 ?? 89 c8 ba cd cc cc cc f7 e2 c1 ea 02 83 e2 fe 8d 04 92 43 39 c8 b8 00 00 00 00 0f 44 d8 41 39 } //10
	condition:
		((#a_01_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}