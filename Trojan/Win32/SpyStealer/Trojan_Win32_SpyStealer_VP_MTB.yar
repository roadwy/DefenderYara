
rule Trojan_Win32_SpyStealer_VP_MTB{
	meta:
		description = "Trojan:Win32/SpyStealer.VP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {7c ff ff ff 0f af 95 90 01 04 89 95 90 01 04 8b 95 90 01 04 39 95 6c ff ff ff 90 00 } //0a 00 
		$a_02_1 = {0f af 75 88 89 b5 90 01 04 8d b3 90 01 04 0f af 75 d0 89 b5 90 01 04 8d b3 90 01 04 03 75 e4 39 7d c8 89 b5 90 01 04 8d b3 90 01 04 89 b5 48 fe 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}