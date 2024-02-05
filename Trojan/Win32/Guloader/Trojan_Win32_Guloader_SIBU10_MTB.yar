
rule Trojan_Win32_Guloader_SIBU10_MTB{
	meta:
		description = "Trojan:Win32/Guloader.SIBU10!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {71 81 34 07 90 01 04 90 02 ac 83 c0 04 90 02 a0 3d 74 18 01 00 90 02 2a 0f 85 e8 fd ff ff 90 02 95 ff d7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}