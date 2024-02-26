
rule Trojan_Win32_ArkeiStealer_RPZ_MTB{
	meta:
		description = "Trojan:Win32/ArkeiStealer.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 45 f8 8b 45 f8 89 85 58 ff ff ff c7 85 70 ff ff ff 6b 65 72 6e c7 85 74 ff ff ff 65 6c 33 32 c7 85 78 ff ff ff 2e 64 6c 6c 83 a5 7c ff ff ff 00 8d 85 70 ff ff ff 50 ff 55 d4 } //00 00 
	condition:
		any of ($a_*)
 
}