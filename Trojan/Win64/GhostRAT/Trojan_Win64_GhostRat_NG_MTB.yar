
rule Trojan_Win64_GhostRat_NG_MTB{
	meta:
		description = "Trojan:Win64/GhostRat.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 b8 4d 00 00 00 41 b9 4c 00 00 00 e8 bc fc ff ff 48 8d 0d 2d e8 20 00 41 b8 08 00 00 00 41 b9 5a 00 00 00 e8 a4 fc ff ff 48 8d 0d c6 e7 20 00 41 b8 5e 00 00 00 45 31 c9 e8 8f fc ff ff } //2
		$a_01_1 = {88 86 04 01 00 00 e8 23 d9 17 00 48 63 c8 48 89 c8 48 d1 e8 48 f7 e7 48 c1 ea 04 48 89 d0 48 c1 e0 06 48 01 d2 48 29 c2 48 01 ca 0f b6 04 13 88 86 05 01 00 00 } //1
		$a_01_2 = {62 00 75 00 61 00 74 00 6c 00 65 00 2e 00 65 00 78 00 65 00 } //1 buatle.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}