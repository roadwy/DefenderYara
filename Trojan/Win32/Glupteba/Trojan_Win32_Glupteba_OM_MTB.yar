
rule Trojan_Win32_Glupteba_OM_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.OM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b cf c1 e9 05 c7 05 90 02 08 c7 05 90 02 08 89 90 02 03 8b 90 02 03 01 90 02 03 81 3d 90 02 08 90 18 8b 90 02 03 33 90 01 01 33 90 01 01 8d 90 02 03 e8 90 02 04 81 3d 90 02 08 90 18 8b 90 02 03 29 90 02 03 83 90 02 04 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}