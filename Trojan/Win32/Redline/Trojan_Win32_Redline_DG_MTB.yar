
rule Trojan_Win32_Redline_DG_MTB{
	meta:
		description = "Trojan:Win32/Redline.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {88 45 db 0f b6 4d db f7 d9 88 4d db 0f b6 55 db d1 fa 0f b6 45 db c1 e0 07 0b d0 88 55 db 8b 4d dc 8a 55 db 88 54 0d e8 e9 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Redline_DG_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {88 4d db 0f b6 55 db f7 da 88 55 db 0f b6 45 db c1 f8 06 0f b6 4d db c1 e1 02 0b c1 88 45 db 0f b6 55 db f7 da 88 55 db 0f b6 45 db f7 d0 88 45 db 0f b6 4d db 83 e9 28 88 4d db } //00 00 
	condition:
		any of ($a_*)
 
}