
rule Trojan_Win64_BlackWidow_GVH_MTB{
	meta:
		description = "Trojan:Win64/BlackWidow.GVH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {45 8a 14 10 [0-32] 44 30 14 0f [0-32] 48 ff c1 [0-32] 48 89 c8 [0-32] 48 81 f9 ?? ?? ?? ?? 90 13 [0-32] 48 31 d2 [0-32] 49 f7 f1 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}