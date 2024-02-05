
rule Trojan_Win32_Glupteba_NB_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b d3 c1 e2 04 03 90 02 06 33 90 02 03 33 90 02 03 2b 90 02 03 81 3d 90 02 08 90 18 8b 90 02 06 29 90 02 06 83 90 02 08 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}