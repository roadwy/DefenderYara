
rule Trojan_BAT_CobaltStrike_ZQ_MTB{
	meta:
		description = "Trojan:BAT/CobaltStrike.ZQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 07 02 07 91 1f 24 61 d2 9c 07 17 58 0b 07 02 8e 69 32 ec } //1
		$a_01_1 = {65 78 63 6c 75 73 69 76 65 4f 52 } //1 exclusiveOR
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_BAT_CobaltStrike_ZQ_MTB_2{
	meta:
		description = "Trojan:BAT/CobaltStrike.ZQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 04 6f 1e 00 00 0a 13 06 00 06 7e 1f 00 00 04 11 06 6f 1f 00 00 0a d2 6f 20 00 00 0a 00 00 11 04 6f 21 00 00 0a 2d d8 } //1
		$a_01_1 = {47 45 4d 53 5c 47 45 4d 53 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 47 45 4d 53 2e 70 64 62 } //1 GEMS\GEMS\obj\Release\GEMS.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}