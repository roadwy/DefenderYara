
rule Trojan_Win32_Zenpak_B_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 4d 6f 76 69 6e 67 2e 68 65 61 76 65 6e 70 75 6d } //01 00  IMoving.heavenpum
		$a_01_1 = {48 61 76 65 44 4a 55 34 45 61 52 67 6d 75 6c 74 69 70 6c 79 } //01 00  HaveDJU4EaRgmultiply
		$a_01_2 = {45 4c 65 73 73 65 72 6d 6f 76 65 74 68 66 69 72 73 74 68 69 6d 52 70 42 69 61 } //01 00  ELessermovethfirsthimRpBia
		$a_01_3 = {38 6f 77 6e 6d 61 6e 68 6f 6e 65 2c 66 6f 72 6d 73 65 65 64 78 } //01 00  8ownmanhone,formseedx
		$a_01_4 = {6f 66 73 61 79 69 6e 67 66 4e 6d 6f 76 65 64 73 65 61 73 } //01 00  ofsayingfNmovedseas
		$a_01_5 = {6d 69 64 73 74 74 68 61 74 74 68 65 72 65 77 } //01 00  midstthattherew
		$a_01_6 = {7a 74 68 65 72 65 67 72 61 73 73 63 72 65 61 74 65 64 6d } //01 00  ztheregrasscreatedm
		$a_01_7 = {71 59 49 78 55 42 65 67 69 6e 6e 69 6e 67 6d 68 69 6d 65 61 72 74 68 } //00 00  qYIxUBeginningmhimearth
	condition:
		any of ($a_*)
 
}