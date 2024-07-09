
rule Trojan_Win32_Redline_GEG_MTB{
	meta:
		description = "Trojan:Win32/Redline.GEG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 83 e0 ?? 8a 98 ?? ?? ?? ?? 32 df e8 ?? ?? ?? ?? 8b f8 8b 0f 8b 49 ?? 8b 4c 39 ?? 8b 49 ?? 89 4c 24 ?? 8b 11 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}