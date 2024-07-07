
rule Trojan_Win32_Redline_DE_MTB{
	meta:
		description = "Trojan:Win32/Redline.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 45 fc b8 d6 38 00 00 01 45 fc 8b 45 08 8b 4d fc 8a 0c 01 8b 15 f8 59 46 00 88 0c 02 } //1
		$a_00_1 = {89 45 fc 8b c6 c1 e8 05 03 45 e8 8b ce c1 e1 04 03 4d e0 33 c1 33 45 fc 89 45 0c 8b 45 0c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}
rule Trojan_Win32_Redline_DE_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 4d db 0f b6 45 db 2d c2 00 00 00 88 45 db 0f b6 4d db f7 d1 88 4d db 0f b6 55 db 03 55 dc 88 55 db 0f b6 45 db f7 d0 88 45 db 0f b6 4d db 81 e9 a3 00 00 00 88 4d db 8b 55 dc 8a 45 db 88 44 15 e8 e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Redline_DE_MTB_3{
	meta:
		description = "Trojan:Win32/Redline.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 45 a3 0f b6 4d a3 33 4d a4 88 4d a3 0f b6 55 a3 2b 55 a4 88 55 a3 0f b6 45 a3 f7 d0 88 45 a3 0f b6 4d a3 33 4d a4 88 4d a3 0f b6 55 a3 f7 d2 88 55 a3 0f b6 45 a3 33 45 a4 88 45 a3 8b 4d a4 8a 55 a3 88 54 0d b0 e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Redline_DE_MTB_4{
	meta:
		description = "Trojan:Win32/Redline.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 4d a3 0f b6 55 a3 33 55 a4 88 55 a3 0f b6 45 a3 2b 45 a4 88 45 a3 0f b6 4d a3 f7 d1 88 4d a3 0f b6 55 a3 33 55 a4 88 55 a3 0f b6 45 a3 f7 d0 88 45 a3 0f b6 4d a3 33 4d a4 88 4d a3 8b 55 a4 8a 45 a3 88 44 15 b0 e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}