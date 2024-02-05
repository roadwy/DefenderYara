
rule Trojan_Win32_Guloader_SIBU6_MTB{
	meta:
		description = "Trojan:Win32/Guloader.SIBU6!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {f8 81 34 1a 90 01 04 90 02 40 43 90 02 30 43 90 02 2a 43 90 02 30 43 90 02 35 81 fb b0 0d 01 00 90 02 2a 0f 85 a9 fe ff ff 90 08 b5 01 ff d2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}