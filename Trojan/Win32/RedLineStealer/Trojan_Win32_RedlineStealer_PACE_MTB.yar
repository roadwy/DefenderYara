
rule Trojan_Win32_RedlineStealer_PACE_MTB{
	meta:
		description = "Trojan:Win32/RedlineStealer.PACE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 45 db f7 d8 88 45 db 0f b6 4d db 2b 4d dc 88 4d db 0f b6 55 db f7 d2 88 55 db 0f b6 45 db 2b 45 dc 88 45 db 0f b6 4d db c1 f9 02 0f b6 55 db c1 e2 06 0b ca 88 4d db 0f b6 45 db 2d ac 90 01 03 88 45 db 0f b6 4d db f7 d9 88 4d db 0f b6 55 db 83 ea 7c 88 55 db 0f b6 45 db f7 d8 90 00 } //01 00 
		$a_03_1 = {88 45 db 0f b6 4d db 03 4d dc 88 4d db 0f b6 55 db f7 d2 88 55 db 0f b6 45 db 2d e2 90 01 03 88 45 db 0f b6 4d db f7 d1 88 4d db 0f b6 55 db 83 c2 4f 88 55 db 0f b6 45 db d1 f8 0f b6 4d db 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}