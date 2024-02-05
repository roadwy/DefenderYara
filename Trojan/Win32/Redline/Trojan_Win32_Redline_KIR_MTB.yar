
rule Trojan_Win32_Redline_KIR_MTB{
	meta:
		description = "Trojan:Win32/Redline.KIR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {51 83 65 fc 00 8b 45 0c 90 01 45 fc 8b 45 08 8b 4d fc 31 08 } //01 00 
		$a_03_1 = {c1 e8 05 03 45 90 01 01 03 f2 33 f0 33 75 90 01 01 c7 05 90 01 08 89 75 90 01 01 8b 45 90 01 01 29 45 fc 89 7d f8 8b 45 90 01 01 01 45 f8 2b 5d f8 ff 4d 90 01 01 89 5d 90 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}