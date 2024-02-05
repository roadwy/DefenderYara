
rule Trojan_Win32_Glupteba_NH_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.NH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 e8 d3 e0 c1 90 02 03 03 90 02 06 55 03 90 02 06 89 90 02 03 e8 90 02 04 33 90 02 03 89 90 02 06 c7 05 90 02 08 8b 90 02 06 29 90 02 03 81 3d 90 02 08 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}