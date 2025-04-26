
rule Backdoor_Win64_Androm_LKH_MTB{
	meta:
		description = "Backdoor:Win64/Androm.LKH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 44 24 29 0f b6 44 24 20 c0 e0 02 c0 f9 04 0a c8 41 c0 e0 04 0f b6 c2 88 4c 24 28 c0 f8 02 49 8b cc c0 e2 06 41 0a c0 0a 54 24 23 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}