
rule Trojan_Win32_Glupteba_MK_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b c6 c1 e8 05 8d 90 02 03 89 90 02 05 e8 90 02 04 8b 90 02 03 8d 90 02 03 e8 90 02 04 33 90 02 03 8d 90 02 03 8b d0 89 90 02 03 c7 05 90 02 08 e8 90 02 04 81 90 02 09 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}