
rule TrojanDropper_Win64_XWorm_AHD_MTB{
	meta:
		description = "TrojanDropper:Win64/XWorm.AHD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {44 89 7d e7 41 8b c7 0f 1f 40 00 66 66 0f 1f 84 00 00 00 00 00 8b 4d e7 30 4c 05 0f 48 ff c0 48 83 f8 ?? 72 } //30
		$a_81_1 = {25 73 25 6c 6c 78 2e 74 6d 70 } //20 %s%llx.tmp
	condition:
		((#a_03_0  & 1)*30+(#a_81_1  & 1)*20) >=50
 
}