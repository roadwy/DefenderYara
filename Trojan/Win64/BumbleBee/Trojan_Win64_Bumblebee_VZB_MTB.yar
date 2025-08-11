
rule Trojan_Win64_Bumblebee_VZB_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.VZB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {4d 63 c1 41 f7 fa 41 ff c2 34 27 0f b6 c8 43 0f b6 04 30 0f af c1 43 88 04 30 8b 15 cc 6b 18 00 8d 04 12 81 f2 29 0c 00 00 48 63 c8 48 8b 05 7d 6b 18 00 21 14 88 0f b6 0d ?? ?? ?? ?? 48 8b 05 64 6b 18 00 44 3b 14 88 7d } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}