
rule Trojan_Win32_Tixinbir_A{
	meta:
		description = "Trojan:Win32/Tixinbir.A,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 } //01 00  \windows\system32\rundll32.exe
		$a_00_1 = {5c 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00 5c 00 } //01 00  \appdata\
		$a_00_2 = {75 00 70 00 64 00 61 00 74 00 65 00 } //01 00  update
		$a_00_3 = {2f 00 69 00 3a 00 } //01 00  /i:
		$a_00_4 = {2e 00 64 00 61 00 74 00 } //00 00  .dat
	condition:
		any of ($a_*)
 
}