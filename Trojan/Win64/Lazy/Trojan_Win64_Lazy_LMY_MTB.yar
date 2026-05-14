
rule Trojan_Win64_Lazy_LMY_MTB{
	meta:
		description = "Trojan:Win64/Lazy.LMY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {32 41 0a 34 f4 0f b6 c0 66 89 41 0a 0f b6 c2 32 41 0c 34 31 0f b6 c0 66 89 41 0c 0f b6 c2 32 41 0e 34 6e 0f b6 c0 66 89 41 0e 0f b6 c2 } //10
		$a_01_1 = {32 41 02 0f b6 c0 66 89 41 02 0f b6 c2 32 41 04 34 3d 0f b6 c0 66 89 41 04 0f b6 c2 32 41 06 34 7a 0f b6 c0 66 89 41 06 0f b6 c2 } //20
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*20) >=30
 
}