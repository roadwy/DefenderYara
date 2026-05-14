
rule Trojan_Win64_DLllHijack_AHA_MTB{
	meta:
		description = "Trojan:Win64/DLllHijack.AHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 10 41 01 d1 45 0f b6 d9 4d 89 d9 ?? ?? ?? 45 0f b6 23 44 88 20 41 88 13 02 10 0f b6 d2 0f b6 44 14 20 41 ?? 02 49 83 c2 01 49 39 fa 75 } //20
		$a_03_1 = {48 89 c8 48 89 cf 49 f7 e1 48 d1 ea 48 8d 04 92 48 8d 04 42 48 29 c7 41 0f b6 04 38 30 04 0b 48 83 c1 ?? 48 39 ce 75 } //20
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*20) >=20
 
}