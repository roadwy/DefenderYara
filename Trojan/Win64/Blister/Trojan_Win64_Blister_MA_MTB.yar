
rule Trojan_Win64_Blister_MA_MTB{
	meta:
		description = "Trojan:Win64/Blister.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 03 ca 4d 63 d0 41 80 d2 10 49 0b fe 44 8b 51 20 40 d2 de 49 c1 c0 38 66 c1 ee 04 8b 79 1c 66 41 c1 f0 9f 4d 8d 14 12 40 d2 c6 44 8b 41 24 40 80 e6 5d 48 03 fa 40 c0 d6 c9 48 d3 fe 8b 71 18 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}