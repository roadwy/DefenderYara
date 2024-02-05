
rule Trojan_Win32_Redline_ASAR_MTB{
	meta:
		description = "Trojan:Win32/Redline.ASAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 55 08 03 55 fc 0f b6 02 35 90 01 01 00 00 00 8b 4d 08 03 4d fc 88 01 68 90 00 } //01 00 
		$a_03_1 = {8b 55 08 03 55 fc 0f b6 02 05 90 01 01 00 00 00 8b 4d 08 03 4d fc 88 01 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}