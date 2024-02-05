
rule Trojan_Win32_DCRat_RE_MTB{
	meta:
		description = "Trojan:Win32/DCRat.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 c8 0f b6 c1 8a 84 05 90 01 01 fe ff ff 32 86 90 01 04 88 86 90 01 04 c7 45 fc ff ff ff ff 8b 85 90 01 01 fe ff ff 8b 8d 90 01 01 fe ff ff 46 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}