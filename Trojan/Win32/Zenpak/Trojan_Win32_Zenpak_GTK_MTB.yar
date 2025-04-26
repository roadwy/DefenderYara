
rule Trojan_Win32_Zenpak_GTK_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GTK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b7 54 4d ?? 8b 85 ?? ?? ?? ?? 0f b7 4c 45 ?? 33 d1 8b 85 ?? ?? ?? ?? 66 89 54 45 ?? ?? ?? b9 02 00 00 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}