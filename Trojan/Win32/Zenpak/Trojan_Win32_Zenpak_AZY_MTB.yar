
rule Trojan_Win32_Zenpak_AZY_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.AZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 85 f4 f7 ff ff 83 ad f4 f7 ff ff 64 8a 95 f4 f7 ff ff 8b 85 f8 f7 ff ff 30 14 30 83 ff } //00 00 
	condition:
		any of ($a_*)
 
}