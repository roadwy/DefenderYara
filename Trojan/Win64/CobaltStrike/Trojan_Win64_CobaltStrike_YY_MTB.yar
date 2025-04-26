
rule Trojan_Win64_CobaltStrike_YY_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.YY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {45 0f b6 74 3d 00 41 30 de e8 ?? ?? ?? ?? 99 f7 fe fe c2 44 30 f2 41 88 14 3f 48 ff c7 49 39 fc 75 } //1
		$a_03_1 = {41 0f b6 1c 3f 44 30 f3 41 88 1c 3f e8 ?? ?? ?? ?? 99 f7 fe fe c2 30 da 41 88 14 3f 48 ff c7 48 39 fe 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}