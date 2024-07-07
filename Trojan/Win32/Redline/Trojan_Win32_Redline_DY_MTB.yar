
rule Trojan_Win32_Redline_DY_MTB{
	meta:
		description = "Trojan:Win32/Redline.DY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 55 db 0f b6 45 db c1 f8 03 0f b6 4d db c1 e1 05 0b c1 88 45 db 0f b6 55 db 81 ea a7 00 00 00 88 55 db 0f b6 45 db f7 d8 88 45 db 0f b6 4d db 81 e9 eb 00 00 00 88 4d db 8b 55 dc 8a 45 db 88 44 15 e8 e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}