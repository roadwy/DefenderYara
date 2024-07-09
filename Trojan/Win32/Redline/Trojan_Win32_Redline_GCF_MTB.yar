
rule Trojan_Win32_Redline_GCF_MTB{
	meta:
		description = "Trojan:Win32/Redline.GCF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 f7 75 08 0f b6 92 ?? ?? ?? ?? 33 ca 88 4d ff 8b 45 f8 8a 88 ?? ?? ?? ?? 88 4d fd 0f b6 55 ff 8b 45 f8 0f b6 88 ?? ?? ?? ?? 03 ca 8b 55 f8 88 8a ?? ?? ?? ?? 8a 45 fd 88 45 fc 0f b6 4d fc 8b 55 f8 0f b6 82 ?? ?? ?? ?? 2b c1 8b 4d f8 88 81 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}