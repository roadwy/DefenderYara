
rule Backdoor_BAT_XWormRAT_H_MTB{
	meta:
		description = "Backdoor:BAT/XWormRAT.H!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 00 04 20 e8 03 00 00 d8 38 } //2
		$a_01_1 = {20 b8 0b 00 00 20 10 27 00 00 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}