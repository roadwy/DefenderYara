
rule Trojan_Win32_Glupteba_OR_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.OR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b f7 c1 e6 90 01 01 81 90 02 09 90 18 03 90 02 06 81 90 02 09 8b 90 02 03 8d 90 02 02 90 18 8b 90 01 01 c1 90 01 02 c7 05 90 02 08 c7 05 90 02 08 89 90 02 03 8b 90 02 06 01 90 02 03 8b 90 02 03 33 90 01 01 33 90 01 01 8d 90 02 06 e8 90 02 04 8b 90 02 06 29 90 02 03 83 90 02 07 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}