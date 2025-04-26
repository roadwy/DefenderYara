
rule Trojan_Win64_ClipBanker_I_MTB{
	meta:
		description = "Trojan:Win64/ClipBanker.I!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 89 4c 24 30 4c 89 44 24 48 48 89 7c 24 38 41 0f b6 0c 13 41 31 c9 41 0f b6 d9 31 c0 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}