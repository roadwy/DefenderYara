
rule Trojan_Win32_Emotet_DGA_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DGA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 d2 8a 94 0d 90 01 04 03 c2 99 f7 bd 90 01 04 8b 45 10 03 85 90 01 04 8a 08 32 8c 15 90 1b 00 8b 55 10 03 95 90 1b 02 88 0a 90 00 } //01 00 
		$a_81_1 = {7c 45 72 69 36 6f 24 2a 58 4a 59 30 71 52 54 6a 5a 72 47 4c 45 5a 6f 7e 51 53 32 4d 47 } //00 00  |Eri6o$*XJY0qRTjZrGLEZo~QS2MG
	condition:
		any of ($a_*)
 
}