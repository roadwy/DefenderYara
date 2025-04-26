
rule Trojan_Win32_Redline_GFX_MTB{
	meta:
		description = "Trojan:Win32/Redline.GFX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b7 45 dc 99 8b 4d a8 8b 75 ac 33 c8 33 f2 89 8d ?? ?? ?? ?? 89 b5 ?? ?? ?? ?? 8b 95 ?? ?? ?? ?? 0b 95 ?? ?? ?? ?? 75 0e } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}