
rule Trojan_Win32_Vidar_GNI_MTB{
	meta:
		description = "Trojan:Win32/Vidar.GNI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4d 08 03 8d 90 01 04 8a 09 88 08 90 01 02 8b 45 08 03 85 90 01 04 0f b6 00 8b 8d 90 01 04 33 84 8d 90 01 04 8b 8d 90 01 04 03 8d 90 01 04 88 01 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}