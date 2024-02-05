
rule Trojan_Win32_Glupteba_DSP_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.DSP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 4c 24 24 8b 54 24 10 8b f3 c1 ee 05 03 74 24 20 03 f9 03 d3 33 fa 81 3d 90 01 04 f5 03 00 00 c7 05 90 01 04 36 06 ea e9 90 00 } //01 00 
		$a_01_1 = {89 68 04 5d 89 18 5b 81 c4 5c 08 00 00 c2 04 00 } //00 00 
	condition:
		any of ($a_*)
 
}