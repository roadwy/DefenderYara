
rule Trojan_Win32_Zbot_CO_MTB{
	meta:
		description = "Trojan:Win32/Zbot.CO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {02 c2 2a c1 2a 05 90 02 04 43 02 45 0c 04 90 01 01 30 44 33 ff 3b 5d 08 7c b3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}