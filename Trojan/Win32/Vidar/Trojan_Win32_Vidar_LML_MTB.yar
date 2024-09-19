
rule Trojan_Win32_Vidar_LML_MTB{
	meta:
		description = "Trojan:Win32/Vidar.LML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b cb e8 fc 3e 00 00 8b 54 24 1c 8b 4c 24 24 8b 7c 24 28 0f b6 44 14 ?? 03 44 24 20 0f b6 c0 8a 44 04 34 30 04 0e 46 3b f5 0f 8c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}