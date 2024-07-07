
rule Trojan_Win32_Redline_GNC_MTB{
	meta:
		description = "Trojan:Win32/Redline.GNC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c4 08 50 e8 90 01 04 83 c4 04 80 34 1f 90 01 01 43 39 de 0f 85 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Redline_GNC_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GNC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c8 0f b6 f1 ba 90 01 04 e8 90 01 04 50 e8 90 01 04 59 8a 84 35 90 01 04 32 83 90 01 04 88 83 90 01 04 43 89 9d 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Redline_GNC_MTB_3{
	meta:
		description = "Trojan:Win32/Redline.GNC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 14 10 03 ca 0f b6 45 90 01 01 03 c8 81 e1 90 01 04 88 4d 90 01 01 0f b6 4d 90 01 01 03 4d 90 01 01 51 0f b7 55 90 01 01 03 55 90 01 01 52 8b 4d 90 01 01 e8 90 01 04 8a 45 90 01 01 04 90 01 01 88 45 90 01 01 0f b6 4d 90 01 01 0f b7 55 90 01 01 3b ca 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Redline_GNC_MTB_4{
	meta:
		description = "Trojan:Win32/Redline.GNC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b d0 88 55 90 01 01 0f b6 4d 90 01 01 83 c1 90 01 01 88 4d 90 01 01 0f b6 55 90 01 01 f7 d2 88 55 90 01 01 0f b6 45 90 01 01 83 c0 22 88 45 90 01 01 0f b6 4d 90 01 01 f7 d9 88 4d 90 01 01 0f b6 55 90 01 01 03 55 90 01 01 88 55 90 01 01 0f b6 45 90 01 01 f7 d8 88 45 90 01 01 0f b6 4d 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}