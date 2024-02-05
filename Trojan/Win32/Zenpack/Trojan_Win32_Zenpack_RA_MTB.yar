
rule Trojan_Win32_Zenpack_RA_MTB{
	meta:
		description = "Trojan:Win32/Zenpack.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {88 95 f3 fe ff ff c6 85 ef fe ff ff 2e c6 85 eb fe ff ff 53 89 e1 8b b5 e4 fe ff ff 89 71 04 c7 41 08 04 01 00 00 c7 01 00 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}