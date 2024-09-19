
rule Trojan_Win64_StrelaStealer_GZM_MTB{
	meta:
		description = "Trojan:Win64/StrelaStealer.GZM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 c1 81 e1 ?? ?? ?? ?? 42 0f b6 4c ?? ?? 30 0c 02 48 83 c0 ?? 4c 39 c8 } //10
		$a_03_1 = {89 c2 81 e2 ?? ?? ?? ?? 42 0f b6 54 ?? ?? 30 14 01 48 83 c0 ?? 4c 39 c8 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=10
 
}