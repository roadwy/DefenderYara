
rule Trojan_Win32_Vidar_GFB_MTB{
	meta:
		description = "Trojan:Win32/Vidar.GFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {66 89 55 c8 8b 45 ?? 35 28 74 0d e0 8b 4d 94 83 f1 00 66 a3 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 33 c0 8b 4d 8c 03 55 88 13 c1 8b 0d ?? ?? ?? ?? 33 f6 03 ca 13 f0 89 0d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}