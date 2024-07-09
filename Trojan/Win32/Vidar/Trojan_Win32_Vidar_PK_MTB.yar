
rule Trojan_Win32_Vidar_PK_MTB{
	meta:
		description = "Trojan:Win32/Vidar.PK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c2 d3 e8 89 7d e8 89 35 ?? ?? ?? ?? 03 45 ?? 33 c7 31 45 ?? 8b 45 ?? 89 45 ?? 8b 45 ?? 29 45 ?? 8b 45 ?? 89 45 ?? 8b 45 ?? 29 45 ?? ff 4d d8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}