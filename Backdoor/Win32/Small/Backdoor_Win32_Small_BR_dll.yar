
rule Backdoor_Win32_Small_BR_dll{
	meta:
		description = "Backdoor:Win32/Small.BR!dll,SIGNATURE_TYPE_PEHSTR,20 00 20 00 15 00 00 0a 00 "
		
	strings :
		$a_01_0 = {5c 4e 65 74 77 6f 72 6b 5c 43 6f 6e 6e 65 63 74 69 6f 6e 73 5c 70 62 6b 5c 72 61 73 70 68 6f 6e 65 2e 70 62 6b } //0a 00  \Network\Connections\pbk\rasphone.pbk
		$a_01_1 = {5b 50 72 69 6e 74 20 53 63 72 65 65 6e 5d } //0a 00  [Print Screen]
		$a_01_2 = {d7 dc b4 c5 c5 cc bf d5 bc e4 ce aa 3a 25 31 30 2e 25 66 47 2c } //01 00 
		$a_01_3 = {65 78 65 2e 63 76 73 65 76 61 } //01 00  exe.cvseva
		$a_01_4 = {65 78 65 2e 70 73 69 64 68 73 61 } //01 00  exe.psidhsa
		$a_01_5 = {65 78 65 2e 63 63 67 76 61 } //01 00  exe.ccgva
		$a_01_6 = {65 78 65 2e 73 73 64 62 } //01 00  exe.ssdb
		$a_01_7 = {65 78 65 2e 72 65 64 69 70 73 } //01 00  exe.redips
		$a_01_8 = {65 78 65 2e 70 76 61 } //01 00  exe.pva
		$a_01_9 = {65 78 65 2e 6e 72 6b 32 33 64 6f 6e } //01 00  exe.nrk23don
		$a_01_10 = {65 78 65 2e 6c 72 74 63 6f 64 69 77 65 } //01 00  exe.lrtcodiwe
		$a_01_11 = {65 78 65 2e 64 6c 65 69 68 73 63 6d } //01 00  exe.dleihscm
		$a_01_12 = {65 78 65 2e 73 65 72 69 66 76 61 70 } //01 00  exe.serifvap
		$a_01_13 = {65 78 65 2e 70 70 61 63 63 } //01 00  exe.ppacc
		$a_01_14 = {65 78 65 2e 6e 6f 6d 74 6e 63 63 70 } //01 00  exe.nomtnccp
		$a_01_15 = {65 78 65 2e 32 33 6d 73 73 66 } //01 00  exe.23mssf
		$a_01_16 = {65 78 65 2e 74 72 61 74 73 76 61 6b } //01 00  exe.tratsvak
		$a_01_17 = {65 78 65 2e 69 75 67 65 } //01 00  exe.iuge
		$a_01_18 = {65 78 65 2e 6e 6f 6d 76 61 72 } //01 00  exe.nomvar
		$a_01_19 = {65 78 65 2e 70 78 76 72 73 76 6b } //01 00  exe.pxvrsvk
		$a_01_20 = {65 78 65 2e 74 6e 65 67 61 64 62 } //00 00  exe.tnegadb
	condition:
		any of ($a_*)
 
}