
rule Trojan_Win32_Glupteba_MA_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {7e 49 55 8b 2d 90 01 04 8b ff 81 ff 85 02 00 00 75 14 90 00 } //0a 00 
		$a_00_1 = {30 04 1e 81 ff 91 05 00 00 75 0e } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Glupteba_MA_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 06 46 85 c0 74 1d bb 90 02 04 8b d6 c7 45 90 02 05 d1 c0 8a fc 8a e6 d1 cb ff 4d fc 75 f3 8b c3 aa 49 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}