
rule PWS_Win32_Cimuz_C{
	meta:
		description = "PWS:Win32/Cimuz.C,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {5c 45 78 70 6c 6f 72 65 72 5c 62 72 6f 77 73 65 72 20 68 65 6c 70 65 72 20 6f 62 4a 65 63 74 73 5c } //01 00  \Explorer\browser helper obJects\
		$a_01_1 = {43 6f 6e 66 6f 72 6d 61 6e 63 65 20 72 61 6e 6b 69 6e 67 } //04 00  Conformance ranking
		$a_01_2 = {31 38 39 37 5b 32 5d 2c 20 61 6e 64 20 64 75 62 62 65 64 20 22 70 6c 61 73 6d 61 22 } //02 00  1897[2], and dubbed "plasma"
		$a_01_3 = {2e 70 68 70 73 00 00 6d 61 69 6e 2e 70 68 70 } //02 00 
		$a_01_4 = {79 65 73 00 45 6e 61 62 6c 65 20 42 72 6f 77 73 } //02 00  敹s湅扡敬䈠潲獷
		$a_01_5 = {c6 85 00 ff ff ff 50 c6 85 fc ef ff ff 7a } //00 00 
	condition:
		any of ($a_*)
 
}