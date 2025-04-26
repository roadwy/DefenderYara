
rule Trojan_Win32_Redline_GMA_MTB{
	meta:
		description = "Trojan:Win32/Redline.GMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 06 83 c4 ?? 0f b6 0f 03 c8 0f b6 c1 8b 8d ?? ?? ?? ?? 8a 84 05 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 41 89 8d ?? ?? ?? ?? 81 f9 ?? ?? ?? ?? 8b 8d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Redline_GMA_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 45 db 03 45 dc 88 45 db 0f b6 4d db c1 f9 06 0f b6 55 db c1 e2 02 0b ca 88 4d db 0f b6 45 db 05 ?? ?? ?? ?? 88 45 db 0f b6 4d db f7 d9 88 4d db } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}