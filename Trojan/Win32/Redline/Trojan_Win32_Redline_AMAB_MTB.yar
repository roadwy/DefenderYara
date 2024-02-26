
rule Trojan_Win32_Redline_AMAB_MTB{
	meta:
		description = "Trojan:Win32/Redline.AMAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f b6 4d db c1 f9 05 0f b6 55 db c1 e2 03 0b ca 88 4d db 0f b6 45 db 03 45 dc 88 45 db 0f b6 4d db f7 d1 88 4d db 0f b6 55 db c1 fa 06 0f b6 45 db c1 e0 02 0b d0 88 55 db } //01 00 
		$a_01_1 = {33 c6 f6 2f 47 e2 ab 5f 5e 5b 5d } //00 00 
	condition:
		any of ($a_*)
 
}