
rule Trojan_Win32_Mapanna{
	meta:
		description = "Trojan:Win32/Mapanna,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 3c 00 72 00 6b 00 3e 00 } //01 00  http://<rk>
		$a_00_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 76 00 76 00 } //01 00  http://vv
		$a_00_2 = {3c 00 63 00 69 00 6b 00 3e 00 } //01 00  <cik>
		$a_00_3 = {3c 00 63 00 69 00 67 00 3e 00 } //01 00  <cig>
		$a_00_4 = {3c 00 72 00 67 00 3e 00 } //01 00  <rg>
		$a_00_5 = {7b 00 54 00 41 00 42 00 7d 00 } //01 00  {TAB}
		$a_01_6 = {c7 85 6c ff ff ff 0b 00 00 00 ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}