
rule Trojan_Win32_Atmrod_B{
	meta:
		description = "Trojan:Win32/Atmrod.B,SIGNATURE_TYPE_PEHSTR,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {61 74 6d 61 70 70 2e 65 78 65 } //1 atmapp.exe
		$a_01_1 = {63 3a 5c 61 74 6d 5c 31 } //1 c:\atm\1
		$a_01_2 = {58 66 73 3a 3a 51 75 65 72 79 43 61 73 68 55 6e 69 74 73 46 72 6f 6d 41 74 6d 34 } //1 Xfs::QueryCashUnitsFromAtm4
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}