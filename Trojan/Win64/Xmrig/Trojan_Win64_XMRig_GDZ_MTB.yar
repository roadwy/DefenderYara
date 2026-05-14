
rule Trojan_Win64_XMRig_GDZ_MTB{
	meta:
		description = "Trojan:Win64/XMRig.GDZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b 47 10 44 32 1c 10 45 88 1c 0a 0f b6 03 a8 01 41 0f 94 c2 0f 85 ?? ?? ?? ?? d1 e8 4c 89 c1 49 39 c0 0f 82 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}