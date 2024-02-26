
rule Backdoor_BAT_XWorm_MBJR_MTB{
	meta:
		description = "Backdoor:BAT/XWorm.MBJR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 56 71 51 d0 b8 d0 b8 4d d0 b8 d0 b8 d0 b8 d0 b8 45 d0 b8 d0 b8 d0 b8 d0 b8 2f 2f 38 d0 b8 d0 b8 4c 67 d0 b8 d0 b8 d0 b8 } //01 00 
		$a_01_1 = {34 39 30 36 2d 62 64 38 39 2d 34 62 39 35 38 62 30 64 30 63 31 63 } //00 00  4906-bd89-4b958b0d0c1c
	condition:
		any of ($a_*)
 
}