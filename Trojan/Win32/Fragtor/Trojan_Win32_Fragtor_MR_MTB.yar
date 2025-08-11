
rule Trojan_Win32_Fragtor_MR_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 03 00 00 "
		
	strings :
		$a_01_0 = {46 65 33 30 34 38 31 32 34 38 33 32 66 30 63 65 66 38 38 33 39 34 31 65 36 30 33 35 65 32 62 62 62 63 32 33 37 2e 65 78 65 } //50 Fe3048124832f0cef883941e6035e2bbbc237.exe
		$a_01_1 = {28 ad c0 14 83 c0 04 eb 0b dd 35 e9 48 a8 46 a1 9e 6a ec 23 83 ea 01 f9 72 } //25
		$a_01_2 = {1f 93 ee 29 42 8a 27 67 13 bb ed 45 28 ad c0 14 83 c0 } //25
	condition:
		((#a_01_0  & 1)*50+(#a_01_1  & 1)*25+(#a_01_2  & 1)*25) >=100
 
}