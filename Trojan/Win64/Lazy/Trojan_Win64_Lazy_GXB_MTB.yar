
rule Trojan_Win64_Lazy_GXB_MTB{
	meta:
		description = "Trojan:Win64/Lazy.GXB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {66 0f 6e c8 66 0f 73 f9 0e 66 0f eb cb 66 0f db ce 66 0f 6f d6 66 0f df d0 66 0f eb d1 66 0f 6f c2 66 0f fc 05 ?? ?? ?? ?? 66 0f 6f c8 66 0f da 0d ?? ?? ?? ?? 66 0f 74 c8 66 0f db 0d ?? ?? ?? ?? 66 0f eb ca f3 0f 7f 0c 2f 48 8d 45 10 48 83 c5 20 4c 39 e5 48 89 c5 0f 86 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}