
rule Backdoor_BAT_Crysan_GFG_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.GFG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b 24 16 2d f8 09 08 11 04 08 8e 69 5d 91 07 11 04 91 61 d2 6f ?? ?? ?? 0a 11 04 13 05 16 2d d7 11 05 17 58 13 04 11 04 07 8e 69 32 d5 16 2d f6 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}