
rule Trojan_BAT_DarkComet_NM_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {58 20 e4 db 9b 28 58 20 cb 52 ca b8 20 e8 2c a2 69 59 59 20 f4 26 7d 94 20 7b 18 00 ab 20 c0 73 82 50 59 20 02 69 fd 09 58 59 61 61 11 06 61 d2 9c 11 06 17 58 13 06 18 13 08 2b 90 d0 01 00 00 04 17 1c 33 03 26 2b 01 26 01 11 06 11 05 8e 69 fe 04 2d 8d } //3
		$a_01_1 = {65 6e 69 7a 75 6d 2e 65 78 65 } //1 enizum.exe
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}