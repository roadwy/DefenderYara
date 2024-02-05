
rule Trojan_Win32_Emotet_ZZ{
	meta:
		description = "Trojan:Win32/Emotet.ZZ,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //0a 00 
		$a_03_1 = {8b c8 8b d6 d3 e2 8b c6 8b cd d3 e0 03 d0 0f be c3 03 d0 8b 44 90 01 02 2b d6 47 8b f2 8a 1f 84 db 75 de 90 00 } //00 00 
		$a_00_2 = {5d 04 00 00 a7 f2 04 80 5c 21 } //00 00 
	condition:
		any of ($a_*)
 
}