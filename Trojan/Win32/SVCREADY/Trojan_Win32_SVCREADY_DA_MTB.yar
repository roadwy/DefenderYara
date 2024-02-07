
rule Trojan_Win32_SVCREADY_DA_MTB{
	meta:
		description = "Trojan:Win32/SVCREADY.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00  DllRegisterServer
		$a_01_1 = {6e 41 71 54 2e 64 6c 6c } //01 00  nAqT.dll
		$a_01_2 = {41 47 62 36 70 61 70 36 34 4d } //01 00  AGb6pap64M
		$a_01_3 = {44 47 51 6a 64 4f 4d 55 67 4f } //01 00  DGQjdOMUgO
		$a_01_4 = {53 65 46 6c 6c 51 42 61 53 4e 75 } //01 00  SeFllQBaSNu
		$a_01_5 = {57 34 5a 62 39 62 4b 6d 6c 39 } //00 00  W4Zb9bKml9
	condition:
		any of ($a_*)
 
}