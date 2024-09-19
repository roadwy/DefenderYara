
rule Trojan_Win64_CobaltStrike_AMX_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.AMX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 f7 e8 41 03 d0 c1 fa 09 8b ca c1 e9 1f 03 d1 69 ca 7b 03 00 00 44 2b c1 41 fe c0 45 32 04 3f 45 32 c6 44 88 07 48 8d 7f 01 48 83 ee 01 75 c2 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win64_CobaltStrike_AMX_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.AMX!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f be 04 08 41 8b d0 33 d0 } //1
		$a_01_1 = {2b c1 48 63 c8 48 8b 44 24 30 88 14 08 e9 8a fd ff ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}