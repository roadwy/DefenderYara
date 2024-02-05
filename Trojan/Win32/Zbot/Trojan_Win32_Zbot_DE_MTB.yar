
rule Trojan_Win32_Zbot_DE_MTB{
	meta:
		description = "Trojan:Win32/Zbot.DE!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 06 46 8a 0f 32 c1 88 07 47 59 4b 74 07 49 75 ee } //00 00 
	condition:
		any of ($a_*)
 
}