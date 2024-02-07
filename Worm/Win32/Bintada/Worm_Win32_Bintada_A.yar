
rule Worm_Win32_Bintada_A{
	meta:
		description = "Worm:Win32/Bintada.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 00 65 00 6d 00 6f 00 72 00 69 00 61 00 20 00 69 00 6e 00 73 00 65 00 72 00 74 00 61 00 64 00 61 00 20 00 2e 00 2e 00 2e 00 } //01 00  Memoria insertada ...
		$a_01_1 = {5b 41 75 74 6f 52 75 6e 5d 06 12 6f 70 65 6e 3d 50 72 6f 6d 6f } //01 00 
		$a_01_2 = {72 65 70 72 6f 64 75 63 69 72 56 69 64 65 6f 54 69 6d 65 72 } //00 00  reproducirVideoTimer
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}