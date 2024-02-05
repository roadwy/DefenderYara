
rule Trojan_Win32_Glupteba_MI_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.MI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b c1 c1 e8 05 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 8b 45 90 01 01 8b 90 01 01 c1 90 01 01 04 03 90 01 02 03 c1 33 90 01 01 81 3d 90 01 08 c7 05 90 01 08 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}