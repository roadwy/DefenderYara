
rule Trojan_Win32_Redline_GKA_MTB{
	meta:
		description = "Trojan:Win32/Redline.GKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c9 8b c1 83 e0 03 8a 80 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 41 81 f9 ?? ?? ?? ?? 72 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Redline_GKA_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {88 4d fe 0f b6 4d fe 8b 45 f8 33 d2 f7 75 f4 0f b6 92 ?? ?? ?? ?? 33 ca 88 4d ff 8b 45 f8 8a 88 ?? ?? ?? ?? 88 4d fd 0f b6 55 ff 8b 45 f8 0f b6 88 ?? ?? ?? ?? 03 ca } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}