
rule Backdoor_Win32_ParalaxRat_DM_MTB{
	meta:
		description = "Backdoor:Win32/ParalaxRat.DM!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 44 8d ec 83 e8 08 6b c0 1f 99 f7 fe 8d 04 16 99 f7 fe 88 54 0d e8 41 89 4d a0 } //0a 00 
		$a_01_1 = {c6 46 24 00 8a cb 80 e1 01 74 16 8a 4d 0c 80 c9 01 0f b6 c1 8b ce 50 8d 44 24 13 } //00 00 
	condition:
		any of ($a_*)
 
}