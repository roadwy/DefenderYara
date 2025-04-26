
rule Trojan_Linux_Hiddad_A_xp{
	meta:
		description = "Trojan:Linux/Hiddad.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {a1 ea 46 f9 f4 03 02 aa f7 03 00 aa 21 00 40 f9 a1 2f 00 f9 82 10 00 b4 } //1
		$a_00_1 = {e1 03 14 aa e0 03 17 aa 42 ac 42 f9 40 00 3f d6 00 7c 40 93 e1 04 00 f0 25 30 44 b9 } //1
		$a_00_2 = {c3 6a 61 38 42 00 03 4a c2 6a 21 38 21 04 00 91 e2 03 03 2a } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}