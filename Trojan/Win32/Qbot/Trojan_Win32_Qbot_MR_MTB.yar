
rule Trojan_Win32_Qbot_MR_MTB{
	meta:
		description = "Trojan:Win32/Qbot.MR!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 55 fc 8d 44 02 01 8b 4d 08 03 01 8b 55 08 89 02 8b 45 08 8b 08 83 e9 01 8b 55 08 89 0a 8b e5 5d c3 } //00 00 
	condition:
		any of ($a_*)
 
}