
rule Trojan_Win32_Vidar_BHN_MTB{
	meta:
		description = "Trojan:Win32/Vidar.BHN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 e8 89 44 24 14 8b 44 24 34 01 44 24 14 8b 44 24 24 31 44 24 10 8b 4c 24 10 8b 54 24 14 51 52 8d 44 24 ?? 50 e8 ?? ?? ?? ?? 8b 4c 24 10 8d 44 24 2c ?? ?? ?? ?? ff 8d 44 24 28 e8 ?? ?? ?? ?? 83 6c 24 ?? ?? 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}