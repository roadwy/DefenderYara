
rule Trojan_Win64_Tiggre_CMM_MTB{
	meta:
		description = "Trojan:Win64/Tiggre.CMM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {8a 49 02 bf ff ff ff ff bb ff ff ff ff d3 e3 89 d9 31 f9 81 e1 46 52 5d 39 81 e3 b9 ad a2 c6 09 cb 81 f3 b9 ad a2 36 44 31 df 31 df 21 df c1 e7 04 44 8d 3c 2f } //1
		$a_00_1 = {41 8a 49 01 be ff ff ff ff d3 e6 31 f7 b8 db bb 27 5f 21 c7 81 e6 24 44 d8 a0 09 fe 44 31 de 31 c6 44 21 de 41 0f b6 09 d3 e6 49 8b 41 18 49 8b 79 28 } //1
		$a_80_2 = {6f 71 63 61 7a 75 37 33 37 77 37 6d 2e 64 6c 6c } //oqcazu737w7m.dll  1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}