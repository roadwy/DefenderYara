
rule Trojan_Win32_Redline_GEA_MTB{
	meta:
		description = "Trojan:Win32/Redline.GEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 f6 8b c6 ba ?? ?? ?? ?? 83 e0 03 8a 98 ?? ?? ?? ?? 32 9e ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b f8 8b 0f 8b 49 04 8b 4c 39 30 8b 49 04 89 4c 24 14 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}