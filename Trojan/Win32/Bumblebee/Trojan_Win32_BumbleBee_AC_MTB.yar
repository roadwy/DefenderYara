
rule Trojan_Win32_BumbleBee_AC_MTB{
	meta:
		description = "Trojan:Win32/BumbleBee.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 05 00 "
		
	strings :
		$a_01_0 = {76 77 65 35 35 34 64 79 38 30 2e 64 6c 6c } //01 00  vwe554dy80.dll
		$a_01_1 = {43 53 6c 53 62 44 34 38 } //01 00  CSlSbD48
		$a_01_2 = {49 54 65 33 30 35 } //01 00  ITe305
		$a_01_3 = {6c 6f 61 64 74 61 73 6b } //05 00  loadtask
		$a_01_4 = {44 52 43 54 46 2e 44 4c 4c } //01 00  DRCTF.DLL
		$a_01_5 = {50 6e 68 75 62 67 79 45 63 74 79 76 } //01 00  PnhubgyEctyv
		$a_01_6 = {52 74 63 66 76 79 4b 6e 62 67 } //01 00  RtcfvyKnbg
		$a_01_7 = {54 73 78 72 64 50 6e 68 62 75 67 } //00 00  TsxrdPnhbug
	condition:
		any of ($a_*)
 
}