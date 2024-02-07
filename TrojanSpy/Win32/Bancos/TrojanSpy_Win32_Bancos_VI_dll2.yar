
rule TrojanSpy_Win32_Bancos_VI_dll2{
	meta:
		description = "TrojanSpy:Win32/Bancos.VI!dll2,SIGNATURE_TYPE_PEHSTR,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 } //01 00  Software\Borland\Delphi
		$a_01_1 = {4d 6f 7a 69 2a 6c 6c 61 2a 43 6f 6e 74 2a 65 6e 74 57 69 2a 6e 64 6f 2a 77 43 6c 2a 61 73 73 } //01 00  Mozi*lla*Cont*entWi*ndo*wCl*ass
		$a_01_2 = {43 2a 68 61 2a 76 65 2a 20 64 2a 65 20 61 2a 63 65 2a 73 2a 73 6f } //01 00  C*ha*ve* d*e a*ce*s*so
		$a_01_3 = {45 64 74 53 65 6e 68 61 } //01 00  EdtSenha
		$a_01_4 = {73 65 6e 68 61 55 73 75 61 72 69 6f } //01 00  senhaUsuario
		$a_01_5 = {69 62 61 6e 6b 3a 3d } //01 00  ibank:=
		$a_01_6 = {70 6e 6c 42 42 50 61 73 73 } //00 00  pnlBBPass
	condition:
		any of ($a_*)
 
}