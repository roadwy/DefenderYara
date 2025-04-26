
rule Trojan_Win32_Redline_VD_MTB{
	meta:
		description = "Trojan:Win32/Redline.VD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 45 db 0f b6 4d db f7 d9 88 4d db 0f b6 55 db 83 ea 49 88 55 db 0f b6 45 db f7 d8 88 45 db 0f b6 4d db f7 d1 88 4d db 8b 55 dc 8a 45 db 88 44 15 e8 e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}