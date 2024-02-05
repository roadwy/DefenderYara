
rule Trojan_Win32_Glupteba_OA_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.OA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {50 5e d3 e0 c1 ee 05 03 90 02 06 03 90 02 06 89 90 02 03 50 59 e8 90 02 04 33 90 01 01 89 90 02 06 89 90 02 05 8b 90 02 06 29 90 02 03 81 3d 90 02 08 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}