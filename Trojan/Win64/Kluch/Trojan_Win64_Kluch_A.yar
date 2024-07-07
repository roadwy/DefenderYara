
rule Trojan_Win64_Kluch_A{
	meta:
		description = "Trojan:Win64/Kluch.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {ed c8 d7 d8 c5 de ff ed df de d6 de dd df d8 e6 ed df de d8 c2 c3 d4 e7 c5 df d4 c3 c3 c4 f2 ed e5 ff 91 c2 c6 de d5 df d8 e6 ed c5 d7 de c2 de c3 d2 d8 fc ed f4 e3 f0 e6 e5 f7 fe e2 ed d4 df d8 d9 d2 d0 fc ed c8 c3 c5 c2 d8 d6 d4 e3 ed 8c e8 f4 fa e3 } //1
		$a_01_1 = {fa fe 91 81 81 83 91 80 9f 80 9e e1 e5 e5 f9 00 85 81 85 91 80 9f 80 9e e1 e5 e5 f9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}