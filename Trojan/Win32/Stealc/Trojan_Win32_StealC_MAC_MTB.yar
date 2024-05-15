
rule Trojan_Win32_StealC_MAC_MTB{
	meta:
		description = "Trojan:Win32/StealC.MAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b de 8b 4d f4 03 c6 8b 55 fc d3 eb 33 d0 03 5d 90 01 01 81 3d 90 01 04 03 0b 00 00 89 5d f0 89 55 fc 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}