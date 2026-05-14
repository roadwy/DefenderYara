
rule Trojan_Win64_LummaStealer_GMH_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.GMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {66 0f 1f 84 00 ?? ?? ?? ?? 48 8b c1 83 e0 03 0f b6 44 10 ?? 32 04 29 88 04 0e 48 ff c1 48 3b cb } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}