
rule Trojan_Win32_RustyStealer_ME_MTB{
	meta:
		description = "Trojan:Win32/RustyStealer.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 45 fc 19 00 00 00 8b c3 0f b6 0e f7 75 fc 41 0f af cb 8a 44 15 d8 30 81 77 af 00 10 43 } //00 00 
	condition:
		any of ($a_*)
 
}