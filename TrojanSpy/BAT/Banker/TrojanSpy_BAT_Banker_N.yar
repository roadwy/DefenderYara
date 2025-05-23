
rule TrojanSpy_BAT_Banker_N{
	meta:
		description = "TrojanSpy:BAT/Banker.N,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {70 72 6f 74 65 67 65 72 20 73 65 75 20 63 6f 6d 70 75 74 61 64 6f 72 20 64 65 20 70 72 6f 67 72 61 6d 61 73 20 6d 61 6c 69 63 69 6f 73 6f 73 } //1 proteger seu computador de programas maliciosos
		$a_01_1 = {71 75 65 20 70 6f 64 65 6d 20 74 65 72 20 61 63 65 73 73 6f 20 61 20 73 65 75 73 20 64 61 64 6f 73 20 63 6f 6e 66 69 64 65 6e 63 69 61 69 73 } //1 que podem ter acesso a seus dados confidenciais
		$a_01_2 = {42 61 6e 63 6f 20 42 72 61 64 65 73 63 6f 20 53 2f 41 } //1 Banco Bradesco S/A
		$a_01_3 = {76 00 65 00 72 00 6d 00 65 00 6c 00 68 00 61 00 62 00 6c 00 6f 00 71 00 64 00 61 00 74 00 61 00 } //1 vermelhabloqdata
		$a_01_4 = {61 00 6d 00 61 00 72 00 65 00 6c 00 61 00 62 00 6c 00 6f 00 71 00 64 00 61 00 74 00 61 00 } //1 amarelabloqdata
		$a_01_5 = {6c 00 61 00 72 00 61 00 6e 00 6a 00 61 00 62 00 6c 00 6f 00 71 00 64 00 61 00 74 00 61 00 } //1 laranjabloqdata
		$a_01_6 = {73 00 61 00 6e 00 74 00 61 00 62 00 6c 00 6f 00 71 00 64 00 61 00 74 00 61 00 } //1 santabloqdata
		$a_01_7 = {76 00 65 00 72 00 64 00 65 00 62 00 6c 00 6f 00 71 00 64 00 61 00 74 00 61 00 } //1 verdebloqdata
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}
rule TrojanSpy_BAT_Banker_N_2{
	meta:
		description = "TrojanSpy:BAT/Banker.N,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0f 00 00 "
		
	strings :
		$a_01_0 = {5c 00 47 00 62 00 50 00 6c 00 75 00 67 00 69 00 6e 00 5c 00 } //1 \GbPlugin\
		$a_01_1 = {64 00 62 00 6f 00 2e 00 69 00 6e 00 66 00 65 00 63 00 74 00 } //1 dbo.infect
		$a_01_2 = {40 00 6e 00 6f 00 6d 00 65 00 70 00 63 00 } //1 @nomepc
		$a_01_3 = {40 00 73 00 65 00 6e 00 68 00 61 00 73 00 } //1 @senhas
		$a_01_4 = {49 00 4e 00 54 00 45 00 52 00 4e 00 45 00 54 00 42 00 41 00 4e 00 4b 00 49 00 4e 00 47 00 43 00 41 00 49 00 58 00 41 00 } //1 INTERNETBANKINGCAIXA
		$a_01_5 = {69 00 74 00 61 00 75 00 2e 00 } //1 itau.
		$a_01_6 = {62 00 61 00 6e 00 63 00 6f 00 62 00 72 00 61 00 73 00 69 00 6c 00 2e 00 } //1 bancobrasil.
		$a_01_7 = {62 00 72 00 61 00 64 00 65 00 73 00 63 00 6f 00 2e 00 } //1 bradesco.
		$a_01_8 = {63 00 61 00 69 00 78 00 61 00 2e 00 } //1 caixa.
		$a_03_9 = {2d 00 20 00 54 00 65 00 63 00 6c 00 61 00 [0-10] 45 00 66 00 65 00 74 00 75 00 61 00 64 00 61 00 21 00 } //1
		$a_01_10 = {76 00 65 00 72 00 6d 00 65 00 6c 00 68 00 61 00 62 00 6c 00 6f 00 71 00 64 00 61 00 74 00 61 00 } //1 vermelhabloqdata
		$a_01_11 = {61 00 6d 00 61 00 72 00 65 00 6c 00 61 00 62 00 6c 00 6f 00 71 00 64 00 61 00 74 00 61 00 } //1 amarelabloqdata
		$a_01_12 = {6c 00 61 00 72 00 61 00 6e 00 6a 00 61 00 62 00 6c 00 6f 00 71 00 64 00 61 00 74 00 61 00 } //1 laranjabloqdata
		$a_01_13 = {73 00 61 00 6e 00 74 00 61 00 62 00 6c 00 6f 00 71 00 64 00 61 00 74 00 61 00 } //1 santabloqdata
		$a_01_14 = {76 00 65 00 72 00 64 00 65 00 62 00 6c 00 6f 00 71 00 64 00 61 00 74 00 61 00 } //1 verdebloqdata
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_03_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1) >=12
 
}
rule TrojanSpy_BAT_Banker_N_3{
	meta:
		description = "TrojanSpy:BAT/Banker.N,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0d 00 00 "
		
	strings :
		$a_01_0 = {5c 00 47 00 62 00 50 00 6c 00 75 00 67 00 69 00 6e 00 5c 00 } //1 \GbPlugin\
		$a_01_1 = {64 00 62 00 6f 00 2e 00 69 00 6e 00 66 00 65 00 63 00 74 00 } //1 dbo.infect
		$a_01_2 = {40 00 6e 00 6f 00 6d 00 65 00 70 00 63 00 } //1 @nomepc
		$a_01_3 = {40 00 73 00 65 00 6e 00 68 00 61 00 73 00 } //1 @senhas
		$a_01_4 = {49 00 4e 00 54 00 45 00 52 00 4e 00 45 00 54 00 42 00 41 00 4e 00 4b 00 49 00 4e 00 47 00 43 00 41 00 49 00 58 00 41 00 } //1 INTERNETBANKINGCAIXA
		$a_01_5 = {69 00 74 00 61 00 75 00 2e 00 } //1 itau.
		$a_01_6 = {62 00 61 00 6e 00 63 00 6f 00 62 00 72 00 61 00 73 00 69 00 6c 00 2e 00 } //1 bancobrasil.
		$a_01_7 = {62 00 72 00 61 00 64 00 65 00 73 00 63 00 6f 00 2e 00 } //1 bradesco.
		$a_01_8 = {63 00 61 00 69 00 78 00 61 00 2e 00 } //1 caixa.
		$a_01_9 = {4f 00 72 00 63 00 61 00 6d 00 65 00 6e 00 74 00 6f 00 20 00 53 00 65 00 67 00 75 00 65 00 20 00 65 00 6d 00 20 00 61 00 6e 00 65 00 78 00 6f 00 21 00 } //1 Orcamento Segue em anexo!
		$a_01_10 = {5b 00 2d 00 20 00 43 00 2e 00 6c 00 2e 00 69 00 2e 00 63 00 2e 00 6b 00 20 00 20 00 45 00 2e 00 66 00 2e 00 65 00 2e 00 74 00 2e 00 75 00 2e 00 61 00 2e 00 64 00 2e 00 6f 00 21 00 20 00 5d 00 } //1 [- C.l.i.c.k  E.f.e.t.u.a.d.o! ]
		$a_01_11 = {5b 00 2d 00 20 00 50 00 65 00 2e 00 64 00 2e 00 69 00 2e 00 64 00 2e 00 6f 00 20 00 20 00 54 00 2e 00 6f 00 2e 00 6b 00 2e 00 65 00 2e 00 6e 00 20 00 20 00 7c 00 20 00 20 00 41 00 2e 00 73 00 2e 00 73 00 20 00 20 00 7c 00 20 00 20 00 53 00 2e 00 65 00 2e 00 72 00 2e 00 69 00 2e 00 61 00 2e 00 6c 00 20 00 45 00 2e 00 66 00 2e 00 65 00 2e 00 74 00 2e 00 75 00 2e 00 61 00 2e 00 64 00 2e 00 61 00 21 00 20 00 5d 00 } //1 [- Pe.d.i.d.o  T.o.k.e.n  |  A.s.s  |  S.e.r.i.a.l E.f.e.t.u.a.d.a! ]
		$a_01_12 = {64 00 62 00 6f 00 2e 00 6c 00 6f 00 67 00 69 00 6e 00 73 00 64 00 61 00 77 00 65 00 62 00 20 00 28 00 4c 00 6f 00 67 00 69 00 6e 00 73 00 2c 00 20 00 54 00 69 00 70 00 6f 00 2c 00 20 00 74 00 69 00 74 00 75 00 6c 00 6f 00 2c 00 } //1 dbo.loginsdaweb (Logins, Tipo, titulo,
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=12
 
}
rule TrojanSpy_BAT_Banker_N_4{
	meta:
		description = "TrojanSpy:BAT/Banker.N,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0e 00 00 "
		
	strings :
		$a_01_0 = {40 00 6e 00 6f 00 6d 00 65 00 70 00 63 00 } //1 @nomepc
		$a_01_1 = {64 00 62 00 6f 00 2e 00 69 00 6e 00 66 00 65 00 63 00 74 00 } //1 dbo.infect
		$a_01_2 = {5c 00 47 00 62 00 50 00 6c 00 75 00 67 00 69 00 6e 00 5c 00 } //1 \GbPlugin\
		$a_01_3 = {40 00 73 00 65 00 6e 00 68 00 61 00 73 00 } //1 @senhas
		$a_01_4 = {5b 00 2d 00 20 00 43 00 2e 00 6c 00 2e 00 69 00 2e 00 63 00 2e 00 6b 00 20 00 20 00 45 00 2e 00 66 00 2e 00 65 00 2e 00 74 00 2e 00 75 00 2e 00 61 00 2e 00 64 00 2e 00 6f 00 21 00 20 00 5d 00 } //1 [- C.l.i.c.k  E.f.e.t.u.a.d.o! ]
		$a_01_5 = {5b 00 20 00 2d 00 20 00 50 00 2e 00 43 00 20 00 20 00 42 00 2e 00 6c 00 2e 00 6f 00 2e 00 71 00 2e 00 75 00 2e 00 65 00 2e 00 61 00 2e 00 64 00 2e 00 6f 00 21 00 20 00 5d 00 } //1 [ - P.C  B.l.o.q.u.e.a.d.o! ]
		$a_01_6 = {5b 00 2d 00 20 00 50 00 65 00 2e 00 64 00 2e 00 69 00 2e 00 64 00 2e 00 6f 00 20 00 20 00 54 00 2e 00 6f 00 2e 00 6b 00 2e 00 65 00 2e 00 6e 00 20 00 20 00 7c 00 20 00 20 00 41 00 2e 00 73 00 2e 00 73 00 20 00 20 00 7c 00 20 00 20 00 53 00 2e 00 65 00 2e 00 72 00 2e 00 69 00 2e 00 61 00 2e 00 6c 00 20 00 45 00 2e 00 66 00 2e 00 65 00 2e 00 74 00 2e 00 75 00 2e 00 61 00 2e 00 64 00 2e 00 61 00 21 00 20 00 5d 00 } //1 [- Pe.d.i.d.o  T.o.k.e.n  |  A.s.s  |  S.e.r.i.a.l E.f.e.t.u.a.d.a! ]
		$a_01_7 = {5b 00 2d 00 20 00 54 00 2e 00 65 00 2e 00 78 00 2e 00 74 00 2e 00 6f 00 20 00 20 00 45 00 2e 00 6e 00 2e 00 76 00 2e 00 69 00 2e 00 61 00 2e 00 64 00 2e 00 6f 00 21 00 20 00 5d 00 } //1 [- T.e.x.t.o  E.n.v.i.a.d.o! ]
		$a_01_8 = {43 00 2e 00 45 00 2e 00 46 00 20 00 7c 00 } //1 C.E.F |
		$a_01_9 = {42 00 2e 00 42 00 20 00 7c 00 } //1 B.B |
		$a_01_10 = {49 00 2e 00 54 00 2e 00 41 00 20 00 7c 00 } //1 I.T.A |
		$a_01_11 = {53 00 2e 00 49 00 2e 00 43 00 2e 00 52 00 2e 00 45 00 2e 00 44 00 20 00 7c 00 } //1 S.I.C.R.E.D |
		$a_01_12 = {53 00 2e 00 41 00 2e 00 4e 00 2e 00 54 00 2e 00 41 00 20 00 7c 00 } //1 S.A.N.T.A |
		$a_01_13 = {42 00 2e 00 52 00 2e 00 41 00 2e 00 44 00 2e 00 41 00 20 00 7c 00 } //1 B.R.A.D.A |
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1) >=12
 
}