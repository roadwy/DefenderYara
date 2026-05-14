
rule TrojanDropper_Win64_XWorm_ARAX_MTB{
	meta:
		description = "TrojanDropper:Win64/XWorm.ARAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 c0 01 99 c1 ea 18 01 d0 0f b6 c0 29 d0 4c 63 c8 42 0f b6 14 0c 89 d1 44 01 d2 41 89 d0 41 c1 f8 1f 41 c1 e8 18 44 01 c2 0f b6 d2 44 29 c2 41 89 d2 48 63 d2 44 0f b6 04 14 46 88 04 0c 88 0c 14 42 02 0c 0c 0f b6 c9 0f b6 14 0c 30 13 48 83 c3 01 48 39 de 75 a9 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}