
rule Trojan_Win32_Veslorn_gen_F{
	meta:
		description = "Trojan:Win32/Veslorn.gen!F,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {79 6f 75 20 77 69 6c 6c 20 63 61 6e 27 74 20 72 65 67 69 73 74 20 70 72 6f 67 72 61 6d 00 } //02 00  潹⁵楷汬挠湡琧爠来獩⁴牰杯慲m
		$a_01_1 = {57 33 32 54 69 6d 65 5c 50 61 72 61 6d 65 74 65 72 73 00 } //04 00 
		$a_01_2 = {00 5c 46 59 44 44 4f 53 2e 64 6c 6c 00 } //04 00 
		$a_01_3 = {00 5c 78 63 6f 70 79 2e 65 78 65 00 } //02 00 
		$a_01_4 = {00 48 6f 6f 6b 69 6e 67 73 20 44 72 69 76 65 72 00 } //00 00 
	condition:
		any of ($a_*)
 
}