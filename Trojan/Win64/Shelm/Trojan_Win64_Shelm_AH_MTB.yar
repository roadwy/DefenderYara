
rule Trojan_Win64_Shelm_AH_MTB{
	meta:
		description = "Trojan:Win64/Shelm.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 01 00 00 "
		
	strings :
		$a_03_0 = {f3 0f 6f 02 48 83 c2 ?? 66 0f ef c1 0f 11 42 f0 48 39 c2 75 ?? 48 8d 93 ?? ?? ?? ?? 0f 1f 40 00 80 30 ?? 48 83 c0 ?? 48 39 d0 75 } //30
	condition:
		((#a_03_0  & 1)*30) >=30
 
}