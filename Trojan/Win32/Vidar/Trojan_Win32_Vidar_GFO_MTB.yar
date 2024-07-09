
rule Trojan_Win32_Vidar_GFO_MTB{
	meta:
		description = "Trojan:Win32/Vidar.GFO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 e8 40 89 45 e8 83 7d ?? ?? 73 ?? 0f be 85 ?? ?? ?? ?? 8b 4d e4 03 4d e8 0f be 09 33 c8 8b 45 e4 03 45 e8 88 08 eb } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}