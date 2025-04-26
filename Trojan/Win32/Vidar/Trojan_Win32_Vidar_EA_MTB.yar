
rule Trojan_Win32_Vidar_EA_MTB{
	meta:
		description = "Trojan:Win32/Vidar.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 f7 29 75 f8 8b 45 e8 29 45 fc 83 6d f0 01 0f 85 ?? ?? ?? ?? 8b 45 08 8b 4d f8 8b 55 f4 5f 5e 89 08 89 50 04 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}