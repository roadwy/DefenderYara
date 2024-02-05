
rule Trojan_Win32_QakBot_RPD_MTB{
	meta:
		description = "Trojan:Win32/QakBot.RPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {03 d8 8b 45 d8 01 18 8b 45 d8 8b 00 8b 55 c4 03 55 a8 03 55 ac 4a 33 c2 89 45 a0 8b 45 d8 8b 55 a0 89 10 33 c0 89 45 a4 8b 45 a8 83 c0 04 03 45 a4 89 45 a8 } //00 00 
	condition:
		any of ($a_*)
 
}