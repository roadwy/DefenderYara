
rule Trojan_Win64_CobaltStrike_YBQ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.YBQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {43 0f b6 44 31 08 0f b6 04 06 88 44 24 68 48 89 44 24 70 48 3d ff } //1
		$a_01_1 = {48 8b 54 24 70 0f b6 4c 24 60 48 8d 76 01 4c 8b 84 24 d8 00 00 00 48 c1 fa 04 c1 e1 02 09 ca 4d 85 c0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}