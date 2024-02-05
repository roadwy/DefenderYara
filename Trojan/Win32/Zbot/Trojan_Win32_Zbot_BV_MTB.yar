
rule Trojan_Win32_Zbot_BV_MTB{
	meta:
		description = "Trojan:Win32/Zbot.BV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 8a 88 90 02 04 30 8c 05 f8 fe ff ff 40 56 89 45 fc e8 90 02 04 59 39 45 fc 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}