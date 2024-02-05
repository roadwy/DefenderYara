
rule Trojan_Win32_Glupteba_NU_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.NU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b f0 c1 ee 05 03 90 02 05 81 3d 90 02 08 c7 05 90 02 08 c7 05 90 02 08 90 18 33 90 02 03 81 90 02 0a 33 90 02 03 2b 90 02 03 83 90 02 05 0f 85 90 00 } //01 00 
		$a_02_1 = {c1 ee 05 03 90 02 03 81 3d 90 02 08 c7 05 90 02 08 c7 05 90 02 08 90 18 90 02 08 33 90 02 03 33 90 02 0c 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}