
rule Trojan_Win32_CobaltStrike_ACO_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.ACO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 30 68 dc 41 40 00 b9 20 60 40 00 e8 90 01 04 c7 45 fc 00 00 00 00 b9 38 60 40 00 6a 30 90 00 } //1
		$a_03_1 = {c7 05 60 60 40 00 00 00 00 00 c7 05 64 60 40 00 0f 00 00 00 c6 05 50 60 40 00 00 e8 90 01 04 c6 45 fc 02 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}