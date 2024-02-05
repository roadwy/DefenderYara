
rule Trojan_Win32_Glupteba_MZK_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.MZK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 0d e4 6e 63 00 8a 8c 01 90 02 04 8b 15 90 02 04 88 0c 02 8b 15 90 02 04 40 3b c2 72 90 00 } //01 00 
		$a_03_1 = {8b 8d a8 fd ff ff 03 c8 c1 e8 05 89 45 90 02 01 c7 05 90 02 03 00 90 02 04 8b 85 9c fd ff ff 01 45 90 1b 00 81 3d 90 02 03 00 90 02 04 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}