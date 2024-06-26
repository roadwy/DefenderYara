
rule Trojan_Win32_Cerobgar_B{
	meta:
		description = "Trojan:Win32/Cerobgar.B,SIGNATURE_TYPE_CMDHSTR_EXT,65 00 65 00 09 00 00 64 00 "
		
	strings :
		$a_02_0 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 90 08 00 01 68 00 74 00 74 00 70 00 90 02 50 3a 00 38 00 30 00 38 00 30 00 90 00 } //01 00 
		$a_00_1 = {2d 00 71 00 } //01 00  -q
		$a_00_2 = {2f 00 71 00 } //01 00  /q
		$a_00_3 = {2d 00 69 00 } //01 00  -i
		$a_00_4 = {2f 00 69 00 } //01 00  /i
		$a_00_5 = {2f 00 66 00 76 00 } //01 00  /fv
		$a_00_6 = {2d 00 66 00 76 00 } //01 00  -fv
		$a_00_7 = {70 00 61 00 63 00 6b 00 61 00 67 00 65 00 } //01 00  package
		$a_00_8 = {71 00 75 00 69 00 65 00 74 00 } //00 00  quiet
	condition:
		any of ($a_*)
 
}