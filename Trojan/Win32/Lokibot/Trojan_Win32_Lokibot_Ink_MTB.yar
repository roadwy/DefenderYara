
rule Trojan_Win32_Lokibot_Ink_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.Ink!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 95 dc fd ff ff 89 94 08 80 00 00 00 8b 86 bc 00 00 00 69 c0 84 00 00 00 03 86 c0 00 00 00 8d 8d f8 fd ff ff e9 } //00 00 
	condition:
		any of ($a_*)
 
}