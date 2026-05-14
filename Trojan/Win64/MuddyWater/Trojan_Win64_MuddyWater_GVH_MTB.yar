
rule Trojan_Win64_MuddyWater_GVH_MTB{
	meta:
		description = "Trojan:Win64/MuddyWater.GVH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {48 83 fa 23 77 2b 44 0f b6 44 0a 02 41 c1 e0 10 44 0f b7 0c 0a 45 01 c8 41 81 c0 ?? ?? ?? ?? 44 33 04 10 44 89 84 14 80 02 00 00 48 83 c2 04 eb cf } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}