
rule Trojan_Win32_IcedId_DEM_MTB{
	meta:
		description = "Trojan:Win32/IcedId.DEM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {83 c4 14 6a 00 6a 01 6a 00 6a 00 8d 55 90 01 01 52 ff 15 90 01 04 85 c0 75 90 01 01 6a 08 6a 01 6a 00 6a 00 8d 45 90 1b 00 50 ff 15 90 1b 01 85 c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}