
rule Trojan_Win32_Andromeda_RPY_MTB{
	meta:
		description = "Trojan:Win32/Andromeda.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 85 54 ff ff ff c6 85 5c fe ff ff 56 c6 85 5d fe ff ff 69 c6 85 5e fe ff ff 72 c6 85 5f fe ff ff 74 c6 85 60 fe ff ff 75 c6 85 61 fe ff ff 61 c6 85 62 fe ff ff 6c c6 85 63 fe ff ff 41 c6 85 64 fe ff ff 6c c6 85 65 fe ff ff 6c } //00 00 
	condition:
		any of ($a_*)
 
}