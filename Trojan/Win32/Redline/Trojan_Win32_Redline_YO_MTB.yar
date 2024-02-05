
rule Trojan_Win32_Redline_YO_MTB{
	meta:
		description = "Trojan:Win32/Redline.YO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {51 83 65 fc 00 8b 45 0c 89 45 fc 8b 45 08 31 45 fc 8b 45 fc 89 01 } //01 00 
		$a_03_1 = {d3 e8 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 33 55 90 01 01 8d 4d 90 01 01 52 ff 75 90 01 01 89 55 90 01 01 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}