
rule Trojan_WinNT_Waltrodock_A{
	meta:
		description = "Trojan:WinNT/Waltrodock.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 4d 94 b8 90 90 90 90 8b 7d 98 8b d1 c1 e9 02 f3 ab 8b ca } //1
		$a_01_1 = {c6 45 dc e9 80 65 dd 00 80 65 de 00 80 65 df 00 80 65 e0 00 83 65 fc 00 8b 4d 08 89 4d d8 66 81 39 4d 5a } //1
		$a_03_2 = {ff d6 84 c0 0f 84 ?? ?? 00 00 83 c3 30 85 db 0f 84 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}