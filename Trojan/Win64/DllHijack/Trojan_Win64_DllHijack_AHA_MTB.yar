
rule Trojan_Win64_DllHijack_AHA_MTB{
	meta:
		description = "Trojan:Win64/DllHijack.AHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {01 d0 44 0f b6 d0 41 29 d2 49 63 c2 48 01 c8 0f b6 10 42 88 14 ?? 49 83 c1 ?? 49 81 f9 ?? ?? ?? ?? 88 18 75 } //30
		$a_03_1 = {42 02 44 14 20 0f b6 c0 0f b6 44 04 20 30 01 48 83 c1 ?? 48 39 ca 75 } //20
	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*20) >=50
 
}