
rule Trojan_Win32_Redline_GCM_MTB{
	meta:
		description = "Trojan:Win32/Redline.GCM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 08 88 4d fe 0f b6 4d fe 8b 45 f8 33 d2 be 04 00 00 00 f7 f6 0f b6 92 ?? ?? ?? ?? 33 ca 88 4d ff 8b 45 0c 03 45 f8 8a 08 88 4d fd 0f b6 55 ff 8b 45 0c 03 45 f8 0f b6 08 03 ca 8b 55 0c 03 55 f8 88 0a } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}