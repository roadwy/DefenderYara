
rule Trojan_Win32_Glupteba_PL_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.PL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {c1 e9 05 c7 05 90 02 08 c7 05 90 02 08 89 90 02 03 8b 90 02 06 01 90 02 03 8b 90 02 03 8b 90 02 03 33 90 01 01 33 90 01 01 2b 90 01 01 81 90 02 05 83 90 02 07 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}