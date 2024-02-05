
rule Trojan_Win32_Glupteba_ND_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.ND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b cb c1 e1 04 03 90 02 06 03 90 02 03 33 90 02 03 33 90 02 03 2b 90 02 03 81 3d 90 02 08 90 18 8d 90 02 06 e8 90 02 04 83 90 02 07 0f 85 90 00 } //01 00 
		$a_02_1 = {8b d3 c1 e2 04 03 90 02 06 03 90 02 03 33 90 02 03 33 90 02 03 2b 90 02 03 81 3d 90 02 08 90 18 8d 90 02 06 e8 90 02 04 83 90 02 07 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}