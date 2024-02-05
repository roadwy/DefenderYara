
rule Trojan_Win32_Glupteba_MG_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 89 45 f8 8b 45 e8 01 45 f8 8b 45 f4 8b 90 02 01 c1 e6 04 03 75 d8 03 90 01 01 33 f0 81 3d 90 01 08 c7 05 90 01 08 75 90 00 } //01 00 
		$a_02_1 = {8b c7 c1 e8 05 03 45 e4 c7 05 90 02 08 33 45 dc 33 90 02 02 2b 90 02 01 ff 4d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}