
rule Trojan_Win32_Glupteba_MYL_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.MYL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 ff 89 74 24 18 89 3d 90 01 04 8b 44 24 18 01 05 90 01 04 a1 90 01 04 89 44 24 28 89 7c 24 18 8b 44 24 28 01 44 24 18 8b 44 24 10 33 44 24 18 89 44 24 18 8b 4c 24 18 90 00 } //01 00 
		$a_03_1 = {33 c6 89 44 24 10 8b 44 24 18 31 44 24 10 a1 90 01 04 2b 5c 24 10 3d 93 00 00 00 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}