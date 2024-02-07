
rule Trojan_Win32_Korad_A{
	meta:
		description = "Trojan:Win32/Korad.A,SIGNATURE_TYPE_PEHSTR,04 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 3d 20 46 2e 49 2e 4e 2e 41 2e 4c 2e 49 2e 5a 2e 41 2e 54 2e 49 2e 4f 2e 4e } //01 00  == F.I.N.A.L.I.Z.A.T.I.O.N
		$a_01_1 = {6d 62 41 75 74 6f 43 6c 69 63 6b 49 73 45 6e 61 62 6c 65 64 } //01 00  mbAutoClickIsEnabled
		$a_01_2 = {67 69 52 61 6e 64 6f 6d 4c 69 6e 6b 43 6c 69 63 6b 52 61 74 65 4f 6e 57 65 62 31 20 3d 20 25 64 } //01 00  giRandomLinkClickRateOnWeb1 = %d
		$a_01_3 = {4c 6f 6f 70 30 31 5b 25 64 5d 2e 73 43 68 6b 55 52 4c 20 3d 20 25 73 } //00 00  Loop01[%d].sChkURL = %s
	condition:
		any of ($a_*)
 
}