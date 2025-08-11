
rule Trojan_Win32_Rugmi_HB_MTB{
	meta:
		description = "Trojan:Win32/Rugmi.HB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,38 00 38 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 55 f8 8b 45 08 03 42 1c 89 45 e4 8b 4d f8 8b 55 08 03 51 24 89 55 e8 8b 45 fc 8b 4d e8 0f b7 14 41 8b 45 e4 8b 4d 08 03 0c 90 8b c1 } //50
		$a_01_1 = {55 8b ec 51 c7 45 fc 00 00 00 00 8b 45 fc 8b 4d 08 0f b7 14 41 85 d2 } //5
		$a_01_2 = {03 0c 90 8b c1 eb } //1
	condition:
		((#a_01_0  & 1)*50+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1) >=56
 
}