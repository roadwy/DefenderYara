
rule Trojan_Win32_Glupteba_PH_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.PH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b c3 c1 e8 05 c7 05 90 02 08 c7 05 90 02 08 89 90 02 03 8b 90 02 06 01 90 02 03 81 3d 90 02 08 90 18 8b 90 02 03 8b 90 02 03 33 90 01 01 33 90 01 01 8d 90 02 06 89 90 02 03 e8 90 02 04 81 90 02 05 83 90 02 07 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}