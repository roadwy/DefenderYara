
rule Trojan_Win32_Redline_GPAJ_MTB{
	meta:
		description = "Trojan:Win32/Redline.GPAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_01_0 = {f7 d1 88 4d db 0f b6 55 db f7 da 88 55 db 0f b6 45 db 2b 45 dc 88 45 db 0f b6 4d db c1 f9 06 } //00 00 
	condition:
		any of ($a_*)
 
}