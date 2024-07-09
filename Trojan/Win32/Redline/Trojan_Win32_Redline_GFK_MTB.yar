
rule Trojan_Win32_Redline_GFK_MTB{
	meta:
		description = "Trojan:Win32/Redline.GFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 83 e0 03 8a 98 ?? ?? ?? ?? 32 1c 37 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 59 0f b6 04 37 8d 0c 03 88 0c 37 2a c8 88 0c 37 46 8b 5d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}