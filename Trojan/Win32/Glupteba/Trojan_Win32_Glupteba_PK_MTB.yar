
rule Trojan_Win32_Glupteba_PK_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.PK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b cf c1 e9 05 c7 05 90 02 08 c7 05 90 02 08 89 90 02 03 8b 90 02 06 01 90 02 03 8b 90 02 03 8b 90 02 03 33 90 01 01 33 90 01 01 8d 90 02 06 e8 90 02 04 81 90 02 05 83 ed 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}