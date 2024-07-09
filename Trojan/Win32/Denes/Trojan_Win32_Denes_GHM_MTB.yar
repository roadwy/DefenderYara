
rule Trojan_Win32_Denes_GHM_MTB{
	meta:
		description = "Trojan:Win32/Denes.GHM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {7a 98 f3 46 c7 45 ?? f3 ec cb 5f c7 45 ?? fc 9d 96 70 c7 45 ?? c2 4e d7 0a c7 45 ?? 39 c6 57 34 c7 45 ?? 58 f8 60 29 c7 45 ?? 82 cf 7a 19 c7 45 ?? 00 31 fa 01 c7 45 ?? 4c cb e1 5d c7 45 ?? 41 2b b2 27 c7 45 ?? 03 ce 67 32 c7 45 ?? 8e f1 8e 41 c7 45 ?? 34 20 d1 67 c7 45 ?? 37 dd e8 61 c7 45 ?? 0f be c9 19 c7 45 ?? 7e 48 6c 15 c7 45 ?? 0e 02 ab 1b c7 45 ?? 19 db 2c 3c c7 45 ?? bb 06 c4 5b c7 45 ?? a7 69 c4 77 c7 45 ?? b7 df 21 76 c7 45 ?? 89 12 4d 4a c7 45 ?? 56 35 64 6a c7 85 ?? ?? ?? ?? d8 4c 91 33 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}