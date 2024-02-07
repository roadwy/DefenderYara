
rule TrojanProxy_Win32_Bedri_G{
	meta:
		description = "TrojanProxy:Win32/Bedri.G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 02 00 "
		
	strings :
		$a_03_0 = {41 4c 49 56 45 7c 7b 90 01 08 2d 90 01 04 2d 90 01 04 2d 90 01 04 2d 90 01 0c 7d 90 00 } //01 00 
		$a_01_1 = {73 30 63 6b 73 39 72 6f 78 79 } //01 00  s0cks9roxy
		$a_01_2 = {62 38 65 64 72 69 33 68 38 6e 62 } //01 00  b8edri3h8nb
		$a_01_3 = {53 54 41 52 54 4f 4b 7c } //01 00  STARTOK|
		$a_01_4 = {35 35 30 20 63 6c 61 72 6b 2e 69 6e 69 } //01 00  550 clark.ini
		$a_01_5 = {47 6c 6f 62 61 6c 5c 64 69 73 67 75 69 73 65 30 35 30 31 } //00 00  Global\disguise0501
	condition:
		any of ($a_*)
 
}