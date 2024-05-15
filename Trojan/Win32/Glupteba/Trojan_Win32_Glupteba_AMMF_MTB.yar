
rule Trojan_Win32_Glupteba_AMMF_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.AMMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 c8 c7 05 90 01 08 8b 45 90 01 01 03 c2 89 4d 90 01 01 33 c1 81 3d 90 01 04 13 02 00 00 89 45 90 01 01 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}