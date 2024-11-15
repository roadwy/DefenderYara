
rule Trojan_Win32_Vidar_AIN_MTB{
	meta:
		description = "Trojan:Win32/Vidar.AIN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c4 08 c7 45 d4 00 00 00 00 c7 45 d8 00 00 00 00 c7 45 dc 00 00 00 00 8b 7d bc 8b 45 c0 0f b6 84 05 ?? ?? ?? ?? 8b 4d 08 30 04 39 47 8b 45 c8 3b 38 8b 55 b8 0f 8d } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}