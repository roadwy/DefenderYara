
rule Trojan_Win64_Tasker_AH_MTB{
	meta:
		description = "Trojan:Win64/Tasker.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {66 0f 6f 00 48 83 c0 ?? 66 0f fd c2 66 0f db c1 0f 29 40 f0 48 39 c8 75 } //30
		$a_03_1 = {66 0f fd c1 66 25 ?? ?? f3 0f 7e 0d ?? ?? ?? ?? 66 89 05 ?? ?? ?? ?? 66 0f db c1 66 0f d6 05 } //20
	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*20) >=50
 
}