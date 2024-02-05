
rule Trojan_Win32_Glupteba_DHE_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.DHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 f6 85 ff 7e 90 01 01 81 ff 90 01 04 90 13 e8 90 01 04 30 04 1e 46 3b f7 7c df 90 00 } //01 00 
		$a_02_1 = {83 ec 50 56 a3 90 01 04 81 05 90 01 08 81 3d 90 01 08 8b 35 90 01 04 90 13 c1 ee 10 81 3d 90 01 08 90 13 8b c6 25 90 01 04 5e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}