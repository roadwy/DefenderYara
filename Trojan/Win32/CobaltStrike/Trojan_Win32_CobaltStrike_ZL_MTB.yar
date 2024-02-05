
rule Trojan_Win32_CobaltStrike_ZL_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.ZL!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 04 71 8a 4c 71 01 88 44 24 10 88 4c 24 14 8b 44 24 10 8b 4c 24 14 25 ff 00 00 00 81 e1 ff 00 00 00 68 48 60 40 00 8d 14 40 8d 04 90 8d bc 41 25 f9 ff ff } //01 00 
		$a_01_1 = {8a 14 16 33 c9 8a cf 32 ca 51 56 8d 4c 24 10 e8 02 17 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}