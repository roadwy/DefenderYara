
rule Trojan_Win64_DllHijack_MKV_MTB{
	meta:
		description = "Trojan:Win64/DllHijack.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 d0 99 f7 f9 48 63 d2 0f b6 84 14 ?? ?? ?? ?? 42 32 04 07 42 88 44 05 00 49 83 c0 01 4c 39 c6 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_Win64_DllHijack_MKV_MTB_2{
	meta:
		description = "Trojan:Win64/DllHijack.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {45 8b c0 4f 8d 44 c7 10 44 8b c8 46 0f b6 4c 0f ?? 44 8b d1 41 c1 fa 1f 41 83 e2 07 44 03 d1 41 83 e2 f8 41 2b ca c1 e1 03 49 d3 e1 4d 31 08 ff c0 3b d0 7f } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}