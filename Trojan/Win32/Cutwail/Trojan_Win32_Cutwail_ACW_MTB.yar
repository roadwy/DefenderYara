
rule Trojan_Win32_Cutwail_ACW_MTB{
	meta:
		description = "Trojan:Win32/Cutwail.ACW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 4d 08 03 4d f0 0f be 11 83 ea 30 0f af 55 f4 03 55 fc 89 55 fc 8b 45 f4 6b c0 0a 89 45 f4 8b 4d f0 83 e9 01 } //00 00 
	condition:
		any of ($a_*)
 
}