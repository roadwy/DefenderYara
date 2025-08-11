
rule Trojan_Win64_DllHijack_C_MTB{
	meta:
		description = "Trojan:Win64/DllHijack.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 8b 08 44 8b 0d ?? ?? ?? ?? 48 03 cf eb ?? 41 0f b7 4c 55 00 48 8b 85 ?? ?? ?? ?? 8b 04 88 48 03 c7 eb ?? 0f b6 c0 48 ff c1 46 8d 0c 48 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}