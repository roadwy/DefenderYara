
rule Trojan_Win32_Glupteba_DSB_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.DSB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {bb 87 d5 7c 3a 81 45 90 01 01 8c eb 73 22 8b 4d 90 01 01 8b 45 90 01 01 8b df d3 e3 8b 0d 90 01 04 8b f7 c1 ee 05 03 5d 90 01 01 03 75 90 01 01 03 c7 33 d8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}