
rule Trojan_Win64_DllHijack_MKV_MTB{
	meta:
		description = "Trojan:Win64/DllHijack.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 d0 99 f7 f9 48 63 d2 0f b6 84 14 ?? ?? ?? ?? 42 32 04 07 42 88 44 05 00 49 83 c0 01 4c 39 c6 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}