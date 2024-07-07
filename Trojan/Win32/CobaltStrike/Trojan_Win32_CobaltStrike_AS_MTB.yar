
rule Trojan_Win32_CobaltStrike_AS_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.AS!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {03 48 3c 89 4d b0 8b 45 b0 83 20 00 33 c0 8b 4d fc 66 89 01 8b 45 fc 83 60 3c 00 } //10
		$a_01_1 = {32 c0 8b 49 50 f3 aa 8b 45 f4 8b 40 50 8b 4d c0 8d 44 01 c0 89 45 98 8b 45 f4 8a 40 10 88 45 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}