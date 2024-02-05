
rule Trojan_Win32_Glupteba_DSD_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.DSD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {bb 87 d5 7c 3a 81 45 90 01 01 8c eb 73 22 8b 45 90 01 01 8b 4d 90 01 01 8b f0 d3 e6 8b c8 c1 e9 05 03 8d 90 01 04 03 b5 90 01 04 89 15 90 01 04 33 f1 8b 4d 90 01 01 03 c8 33 f1 90 00 } //01 00 
		$a_02_1 = {bb 87 d5 7c 3a 81 45 90 01 01 8c eb 73 22 8b 4d 90 01 01 8b d7 d3 e2 8b cf c1 e9 05 03 8d 90 01 04 03 95 90 01 04 33 c0 33 d1 8b 8d 90 01 04 03 cf 33 d1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}