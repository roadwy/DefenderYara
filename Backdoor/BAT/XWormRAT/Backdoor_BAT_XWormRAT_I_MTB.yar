
rule Backdoor_BAT_XWormRAT_I_MTB{
	meta:
		description = "Backdoor:BAT/XWormRAT.I!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 00 04 13 14 7e ?? 00 00 04 13 0b 7e ?? 00 00 04 20 e8 03 00 00 d8 1f } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}