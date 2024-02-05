
rule Trojan_Win32_Glupteba_PIA_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.PIA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 44 24 2c 01 44 24 90 01 01 8b 4c 24 90 01 01 8b 54 24 90 01 01 d3 ea 8b 4c 24 90 01 01 8d 44 24 90 01 01 c7 05 90 01 08 89 54 24 28 e8 90 01 04 8b 44 24 20 31 44 24 10 81 3d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}