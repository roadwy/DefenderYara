
rule PWS_Win32_Lolyda_K{
	meta:
		description = "PWS:Win32/Lolyda.K,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {81 7d 20 0b e0 22 00 75 90 01 01 83 7d 14 04 72 06 83 7d 1c 04 73 08 90 00 } //01 00 
		$a_00_1 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 64 00 65 00 76 00 48 00 42 00 4b 00 65 00 72 00 6e 00 65 00 6c 00 33 00 32 00 } //00 00  \Device\devHBKernel32
	condition:
		any of ($a_*)
 
}