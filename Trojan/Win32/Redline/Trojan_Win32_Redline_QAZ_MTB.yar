
rule Trojan_Win32_Redline_QAZ_MTB{
	meta:
		description = "Trojan:Win32/Redline.QAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {51 83 65 fc 00 8b 45 0c 90 01 45 fc 8b 45 08 8b 4d fc 31 08 } //01 00 
		$a_03_1 = {8b c2 c1 e8 90 01 01 03 45 90 01 01 03 f1 33 f0 33 75 0c c7 05 90 01 08 89 75 fc 8b 45 fc 29 45 08 81 3d 90 01 08 74 90 01 01 68 90 01 04 8d 45 f4 50 e8 90 01 04 ff 4d f0 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}