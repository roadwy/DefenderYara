
rule Trojan_Win32_Lazy_NF_MTB{
	meta:
		description = "Trojan:Win32/Lazy.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 06 00 00 05 00 "
		
	strings :
		$a_81_0 = {30 74 36 2d 2b 43 2a 50 64 32 2b 57 6b 21 65 2b 2d 2e 70 64 62 } //05 00  0t6-+C*Pd2+Wk!e+-.pdb
		$a_81_1 = {74 65 73 74 41 50 50 2e 65 78 45 } //05 00  testAPP.exE
		$a_81_2 = {73 45 4c 46 2e 45 78 65 } //03 00  sELF.Exe
		$a_81_3 = {4b 65 52 4e 65 6c 33 32 2e 44 4c 6c } //01 00  KeRNel32.DLl
		$a_81_4 = {53 65 74 75 70 44 69 44 65 73 74 72 6f 79 44 65 76 69 63 65 49 6e 66 6f 4c 69 73 74 } //01 00  SetupDiDestroyDeviceInfoList
		$a_81_5 = {4d 70 52 65 70 6f 72 74 45 76 65 6e 74 45 78 } //00 00  MpReportEventEx
	condition:
		any of ($a_*)
 
}