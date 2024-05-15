
rule Trojan_Win32_NetLoader_RPY_MTB{
	meta:
		description = "Trojan:Win32/NetLoader.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 55 fc 03 51 3c 89 55 e8 8b 45 e8 8b 4d fc 03 48 78 89 4d e0 8b 55 e0 8b 45 fc 03 42 20 89 45 e4 8b 4d e0 } //00 00 
	condition:
		any of ($a_*)
 
}