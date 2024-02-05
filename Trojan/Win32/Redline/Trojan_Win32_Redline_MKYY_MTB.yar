
rule Trojan_Win32_Redline_MKYY_MTB{
	meta:
		description = "Trojan:Win32/Redline.MKYY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 4d f8 83 25 90 01 05 8d 14 01 8b c8 c1 e1 90 01 01 03 4d 90 01 01 c1 e8 90 01 01 33 ca 03 c3 33 c1 89 55 90 01 01 89 4d 90 01 01 89 45 90 01 01 8b 45 90 01 01 01 05 90 00 } //01 00 
		$a_03_1 = {01 45 fc 83 6d fc 90 01 01 8b 45 90 01 01 8b 4d 90 01 01 31 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}