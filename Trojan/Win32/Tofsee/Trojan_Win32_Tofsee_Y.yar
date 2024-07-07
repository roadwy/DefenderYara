
rule Trojan_Win32_Tofsee_Y{
	meta:
		description = "Trojan:Win32/Tofsee.Y,SIGNATURE_TYPE_PEHSTR_EXT,65 00 65 00 02 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_03_1 = {76 2d 8b 55 08 0f b6 14 11 33 c2 8b d0 83 e2 0f c1 e8 04 33 04 90 01 05 8b d0 83 e2 0f c1 e8 04 33 04 90 01 05 41 3b 4d 0c 72 d3 f7 d0 5d c3 90 00 } //100
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*100) >=101
 
}