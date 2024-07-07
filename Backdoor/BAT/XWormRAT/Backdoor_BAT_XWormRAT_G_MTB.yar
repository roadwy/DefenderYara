
rule Backdoor_BAT_XWormRAT_G_MTB{
	meta:
		description = "Backdoor:BAT/XWormRAT.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 00 04 20 e8 03 00 00 d8 28 } //2
		$a_01_1 = {25 26 14 14 14 17 28 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}