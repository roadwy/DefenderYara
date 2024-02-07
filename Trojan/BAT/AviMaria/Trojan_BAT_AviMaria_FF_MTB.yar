
rule Trojan_BAT_AviMaria_FF_MTB{
	meta:
		description = "Trojan:BAT/AviMaria.FF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 0a 00 0c 00 00 0a 00 "
		
	strings :
		$a_01_0 = {07 28 1f 00 00 0a 03 6f 20 00 00 0a 6f 21 00 00 0a 0c 73 22 00 00 0a 13 06 11 06 08 6f 23 00 00 0a 11 06 18 6f 24 00 00 0a 11 06 18 6f 25 00 00 0a 11 06 0d } //0a 00 
		$a_01_1 = {2b 22 2b 23 2b 28 2b 2a 06 16 06 8e 69 6f 26 00 00 0a 13 05 28 1f 00 00 0a 11 05 6f 27 00 00 0a 13 07 de 26 09 2b db 6f 28 00 00 0a 2b d6 13 04 2b d4 11 04 2b d2 } //01 00 
		$a_01_2 = {73 66 67 70 } //01 00  sfgp
		$a_01_3 = {73 62 66 67 } //01 00  sbfg
		$a_01_4 = {73 66 67 67 66 73 } //01 00  sfggfs
		$a_01_5 = {47 65 65 64 66 64 66 6b 73 } //01 00  Geedfdfks
		$a_01_6 = {44 69 72 65 63 74 66 6e 6f 74 20 66 73 69 73 74 } //01 00  Directfnot fsist
		$a_01_7 = {47 65 66 65 64 66 66 64 66 6b 73 } //01 00  Gefedffdfks
		$a_01_8 = {63 65 6b 72 67 63 68 } //01 00  cekrgch
		$a_01_9 = {66 73 61 64 64 73 64 66 73 61 } //01 00  fsaddsdfsa
		$a_01_10 = {50 6f 77 65 72 65 64 42 79 41 74 74 72 69 62 75 74 65 } //01 00  PoweredByAttribute
		$a_81_11 = {43 3a 5c 73 64 66 64 66 72 79 5c } //00 00  C:\sdfdfry\
	condition:
		any of ($a_*)
 
}