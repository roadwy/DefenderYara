
rule Backdoor_BAT_RemcosRAT_A_MTB{
	meta:
		description = "Backdoor:BAT/RemcosRAT.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {9a 1f 10 28 } //2
		$a_01_1 = {00 00 01 25 16 1f 27 9d 6f } //2
		$a_03_2 = {00 00 01 25 16 20 ?? ?? ?? 00 28 ?? ?? 00 06 a2 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 13 01 38 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_03_2  & 1)*2) >=6
 
}