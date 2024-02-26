
rule Backdoor_BAT_XWormRAT_F_MTB{
	meta:
		description = "Backdoor:BAT/XWormRAT.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {57 55 02 dc 49 0f 00 00 00 fa 01 33 00 16 00 00 02 00 00 00 3e 00 00 00 36 00 00 00 4f 00 00 00 d9 00 00 00 c0 } //01 00 
		$a_01_1 = {43 6f 6d 70 72 65 73 73 53 68 65 6c 6c } //00 00  CompressShell
	condition:
		any of ($a_*)
 
}