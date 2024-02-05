
rule Trojan_Win32_Zbot_Z_MTB{
	meta:
		description = "Trojan:Win32/Zbot.Z!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {83 ff 00 74 90 01 01 83 ef 04 83 c6 04 8b 4e fc 89 8b 90 01 04 83 c3 04 81 ab 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}