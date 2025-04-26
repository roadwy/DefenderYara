
rule Trojan_Win64_GhostRat_DCP_MTB{
	meta:
		description = "Trojan:Win64/GhostRat.DCP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {45 8a 24 11 c4 e3 fd 00 f6 d8 c4 e3 fd 00 ff d8 c5 cd 60 e1 c5 cd 68 f1 c5 c5 60 c1 c5 c5 68 f9 44 30 24 0f c5 fd 60 c2 c5 dd 60 e1 c5 e5 60 dd c5 c5 73 d8 02 c5 fd 69 f4 c5 fd 61 c4 c5 dd 73 dc 02 c5 f5 73 db 02 c5 e5 69 d7 48 ff c1 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}