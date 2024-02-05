
rule Trojan_Win32_Phorpiex_RC_MTB{
	meta:
		description = "Trojan:Win32/Phorpiex.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 7d f8 33 4d fc 89 7d f8 89 4d fc 8b 55 f4 8b 45 08 8b 4d f4 8b 75 08 8b bc d0 18 ff ff ff 23 bc ce f8 fd ff ff 8b 94 d0 1c ff ff ff 23 94 ce fc fd ff ff 33 7d f8 33 55 fc 89 7d f8 89 55 fc } //00 00 
	condition:
		any of ($a_*)
 
}