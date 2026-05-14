
rule Trojan_Win32_Zegost_SX_MTB{
	meta:
		description = "Trojan:Win32/Zegost.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 03 00 00 "
		
	strings :
		$a_01_0 = {c6 45 e0 43 c6 45 e1 6f c6 45 e2 6e c6 45 e3 6e c6 45 e4 65 c6 45 e5 63 c6 45 e6 74 c6 45 e7 47 c6 45 e8 72 c6 45 e9 6f c6 45 ea 75 c6 45 eb 70 } //20
		$a_80_1 = {25 50 72 6f 67 72 61 6d 46 69 6c 65 73 25 5c 52 75 6d 6e 6f 20 51 72 73 74 75 76 } //%ProgramFiles%\Rumno Qrstuv  10
		$a_80_2 = {74 65 6c 72 74 2e 65 78 65 } //telrt.exe  5
	condition:
		((#a_01_0  & 1)*20+(#a_80_1  & 1)*10+(#a_80_2  & 1)*5) >=35
 
}