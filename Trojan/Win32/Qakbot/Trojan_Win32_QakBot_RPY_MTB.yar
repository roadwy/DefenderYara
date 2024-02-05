
rule Trojan_Win32_QakBot_RPY_MTB{
	meta:
		description = "Trojan:Win32/QakBot.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 80 f4 00 00 00 03 86 a4 00 00 00 2b c3 50 8b 46 34 33 c5 50 8b 86 ac 00 00 00 0d 34 1e 00 00 0f af 46 78 56 50 } //01 00 
		$a_03_1 = {50 8b 46 64 33 44 24 2c 03 41 20 8d 8f 51 ff ff ff 50 69 c2 90 01 02 00 00 50 8b c7 35 90 01 02 00 00 05 90 01 02 00 00 50 8b 86 ac 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}