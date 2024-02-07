
rule TrojanSpy_Win32_Webmoner_N{
	meta:
		description = "TrojanSpy:Win32/Webmoner.N,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 57 65 62 4d 6f 6e 65 79 } //01 00  Software\WebMoney
		$a_01_1 = {26 44 41 59 3d } //01 00  &DAY=
		$a_01_2 = {64 61 74 61 2f 2f 73 75 6d } //01 00  data//sum
		$a_01_3 = {3f 75 69 6e 3d } //00 00  ?uin=
	condition:
		any of ($a_*)
 
}