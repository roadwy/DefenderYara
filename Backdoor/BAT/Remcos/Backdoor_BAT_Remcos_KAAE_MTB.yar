
rule Backdoor_BAT_Remcos_KAAE_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.KAAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 08 11 06 08 8e 69 5d 08 11 06 08 8e 69 5d 91 09 11 06 1f 16 5d 6f ?? 00 00 0a 61 28 ?? 00 00 0a 08 11 06 17 58 08 8e 69 5d 91 28 ?? 00 00 0a 59 20 ?? ?? 00 00 58 20 ?? ?? 00 00 5d d2 9c 00 11 06 15 58 13 06 11 06 16 fe 04 16 fe 01 13 07 11 07 2d ac } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}