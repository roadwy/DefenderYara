
rule Trojan_Win32_CobaltStrike_PHQ_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.PHQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {45 0f b6 1c 00 4d 8b 22 4d 0f af dc 4c 01 da 41 88 14 00 48 ff c0 48 c1 fa 08 } //1
		$a_01_1 = {44 0f b6 0c 0e ff c2 44 0f b6 d2 46 8b 1c 90 44 01 df 44 0f b6 e7 46 8b 2c a0 46 89 2c 90 46 89 1c a0 47 8d 14 2b 45 0f b6 d2 46 33 0c 90 44 88 0c 0b 48 ff c1 } //1
		$a_01_2 = {6f 29 65 6c 30 41 26 52 7a 29 6a 41 2a 33 2a 3e 4e 64 4f 52 57 57 } //1 o)el0A&Rz)jA*3*>NdORWW
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}