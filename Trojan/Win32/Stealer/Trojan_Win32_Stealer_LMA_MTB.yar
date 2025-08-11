
rule Trojan_Win32_Stealer_LMA_MTB{
	meta:
		description = "Trojan:Win32/Stealer.LMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 94 08 fc b3 d8 c3 31 ca 89 55 f0 8b 55 f0 80 c2 94 88 94 08 fc b3 d8 c3 41 81 f9 18 4c 27 3c } //20
		$a_01_1 = {09 d6 89 f2 31 da f7 d6 21 de 8d 3c 1a 29 f7 f7 d2 21 fa 8d b1 00 80 16 3d 89 df f7 d7 09 f7 89 c6 09 de 21 f7 01 df 89 d6 31 fe f7 d2 21 fa 8d b8 00 81 e9 c2 21 df 8b 5d ec 01 d2 f7 d2 01 f2 09 fa f7 d2 89 55 f0 8b 55 f0 80 c2 64 } //20
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*20) >=40
 
}