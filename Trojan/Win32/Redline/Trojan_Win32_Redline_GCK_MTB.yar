
rule Trojan_Win32_Redline_GCK_MTB{
	meta:
		description = "Trojan:Win32/Redline.GCK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e0 ?? 03 45 e8 03 ce 33 c1 33 45 08 2b f8 81 3d ?? ?? ?? ?? 93 00 00 00 74 ?? 68 ?? ?? ?? ?? 8d 45 fc 50 e8 ?? ?? ?? ?? ff 4d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}