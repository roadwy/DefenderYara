
rule Trojan_Win32_Matanbuchus_QW_MTB{
	meta:
		description = "Trojan:Win32/Matanbuchus.QW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1d 00 1d 00 05 00 00 "
		
	strings :
		$a_00_0 = {89 45 e4 bb 03 00 00 00 33 5d 08 83 c3 37 2b 5d 10 83 c3 68 } //10
		$a_00_1 = {83 c6 57 81 ee 54 6b b6 93 33 75 1c 81 c6 30 e2 71 d9 } //10
		$a_81_2 = {53 7a 54 6f 57 7a } //3 SzToWz
		$a_81_3 = {43 6d 42 75 69 6c 64 46 75 6c 6c 50 61 74 68 46 72 6f 6d 52 65 6c 61 74 69 76 65 57 } //3 CmBuildFullPathFromRelativeW
		$a_81_4 = {51 6d 37 6b 6c 6a 51 54 52 4b 68 42 63 4f 76 65 33 4a 50 70 77 45 34 58 4f 6f 5a 63 79 } //3 Qm7kljQTRKhBcOve3JPpwE4XOoZcy
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3) >=29
 
}