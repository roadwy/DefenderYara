
rule Trojan_Win32_Trickbot_AN_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 09 89 4e 08 8b 54 3a fc 8b fa 2b f9 89 7e 0c 76 1b 33 ff 33 f6 46 83 ff ?? 7f 0b 8a 1c 38 03 fe 30 19 03 ce eb 02 33 ff 3b ca 72 ea 5f 5b 5e 33 c0 c2 04 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Trickbot_AN_MTB_2{
	meta:
		description = "Trojan:Win32/Trickbot.AN!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {57 6a 12 8b 45 04 83 c0 18 5b 8b f0 53 51 8b 0f 8b 06 33 c1 88 07 46 47 4b 58 8b c8 75 06 58 2b f0 50 8b d8 49 75 e6 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}