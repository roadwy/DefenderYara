
rule Trojan_Win32_Lukicsel_F{
	meta:
		description = "Trojan:Win32/Lukicsel.F,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 57 69 6e 6c 6f 67 6f 6e 4c 6f 67 6f 66 66 45 76 65 6e 74 00 57 69 6e 6c 6f 67 6f 6e 53 74 61 72 74 75 70 45 76 65 6e 74 00 } //01 00  圀湩潬潧䱮杯景䕦敶瑮圀湩潬潧卮慴瑲灵癅湥t
		$a_03_1 = {8d 45 08 e8 90 01 04 32 06 88 07 46 47 4b 75 ef 90 00 } //01 00 
		$a_03_2 = {6a 00 6a 02 ff 15 90 01 04 8b d8 85 db 75 90 01 01 e8 90 01 04 83 f8 02 75 05 e8 90 01 04 68 e8 03 00 00 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}