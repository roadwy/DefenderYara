
rule Trojan_Win32_PovertyStealer_RPX_MTB{
	meta:
		description = "Trojan:Win32/PovertyStealer.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {b9 57 00 00 00 66 89 8d 74 ff ff ff ba 61 00 00 00 66 89 95 76 ff ff ff b8 6c 00 00 00 66 89 85 78 ff ff ff b9 6c 00 00 00 66 89 8d 7a ff ff ff ba 65 00 00 00 66 89 95 7c ff ff ff b8 74 00 00 00 66 89 85 7e ff ff ff b9 73 00 00 00 66 89 4d 80 ba 5c 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}