
rule Trojan_Win32_Mekotio_RS_MTB{
	meta:
		description = "Trojan:Win32/Mekotio.RS!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {75 61 62 6b 36 30 39 34 32 31 6e 30 70 73 7a 65 34 38 33 31 } //01 00  uabk609421n0psze4831
		$a_01_1 = {67 74 6a 32 34 72 37 6b 74 6c 34 37 30 } //01 00  gtj24r7ktl470
		$a_01_2 = {57 69 6e 48 74 74 70 47 65 74 49 45 50 72 6f 78 79 43 6f 6e 66 69 67 46 6f 72 43 75 72 72 65 6e 74 55 73 65 72 } //01 00  WinHttpGetIEProxyConfigForCurrentUser
		$a_01_3 = {74 68 65 6d 69 64 61 } //00 00  themida
	condition:
		any of ($a_*)
 
}