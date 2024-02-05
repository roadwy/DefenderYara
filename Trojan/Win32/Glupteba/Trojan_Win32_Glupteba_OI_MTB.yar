
rule Trojan_Win32_Glupteba_OI_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.OI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b d3 c1 ea 05 8d 90 02 02 c7 90 02 09 c7 90 02 09 89 90 02 03 8b 90 02 03 01 90 02 03 8b 90 01 01 c1 90 02 02 03 90 02 03 33 90 02 03 33 90 01 03 81 90 02 09 75 90 00 } //01 00 
		$a_02_1 = {8b cd c1 e9 05 c7 05 90 02 08 c7 05 90 02 08 89 90 02 03 8b 90 02 06 01 90 02 03 8b 90 02 03 33 90 02 03 33 90 02 03 81 3d 90 02 08 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}