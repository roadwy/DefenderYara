
rule Trojan_Win32_Guloader_SIBU7_MTB{
	meta:
		description = "Trojan:Win32/Guloader.SIBU7!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {50 81 34 07 90 01 04 90 02 aa 83 c0 04 90 02 b0 3d 74 1a 01 00 90 02 30 0f 85 ca fd ff ff 90 02 aa ff d7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}