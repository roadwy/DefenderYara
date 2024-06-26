
rule Trojan_Win32_Autophyte_H_dha{
	meta:
		description = "Trojan:Win32/Autophyte.H!dha,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 16 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 70 72 46 6a 70 67 79 4b 61 77 6a 70 50 6d 41 } //01 00  GprFjpgyKawjpPmA
		$a_01_1 = {47 70 72 44 65 70 6e 56 70 79 50 6d 41 } //01 00  GprDepnVpyPmA
		$a_01_2 = {47 70 72 50 6e 6a 78 56 70 79 50 6d 41 } //01 00  GprPnjxVpyPmA
		$a_01_3 = {47 70 72 46 6a 70 67 79 54 6e 71 64 56 70 79 41 } //01 00  GprFjpgyTnqdVpyA
		$a_01_4 = {47 70 72 43 67 70 61 69 70 56 70 79 41 } //01 00  GprCgpaipVpyA
		$a_01_5 = {47 70 72 74 68 69 70 67 48 70 67 6b 74 63 70 43 69 67 77 53 61 6e 6f 77 70 67 41 } //01 00  GprthipgHpgktcpCigwSanowpgA
		$a_01_6 = {47 70 72 43 77 64 68 70 56 70 79 } //01 00  GprCwdhpVpy
		$a_01_7 = {74 6e 70 69 5f 61 6f 6f 67 } //01 00  tnpi_aoog
		$a_01_8 = {5f 5f 4c 48 41 51 4f 54 68 48 70 69 } //01 00  __LHAQOThHpi
		$a_01_9 = {74 64 63 69 77 68 64 63 76 70 69 } //01 00  tdciwhdcvpi
		$a_01_10 = {4c 48 41 52 70 69 57 61 68 69 50 67 67 64 67 } //01 00  LHARpiWahiPggdg
		$a_01_11 = {63 77 64 68 70 68 64 63 76 70 69 } //01 00  cwdhphdcvpi
		$a_01_12 = {4c 48 41 48 69 61 67 69 6a 65 } //01 00  LHAHiagije
		$a_01_13 = {4c 48 41 43 77 70 61 6e 6a 65 } //01 00  LHACwpanje
		$a_01_14 = {52 70 69 57 64 72 74 63 61 77 4f 67 74 6b 70 68 } //01 00  RpiWdrtcawOgtkph
		$a_01_15 = {43 67 70 61 69 70 45 67 64 63 70 68 68 41 } //01 00  CgpaipEgdcphhA
		$a_01_16 = {52 70 69 49 70 78 65 45 61 69 73 41 } //01 00  RpiIpxeEaisA
		$a_01_17 = {43 67 70 61 69 70 49 64 64 77 73 70 77 65 33 32 48 6e 61 65 68 73 64 69 } //01 00  CgpaipIddwspwe32Hnaehsdi
		$a_01_18 = {48 70 69 51 74 77 70 45 64 74 6e 69 70 67 } //01 00  HpiQtwpEdtnipg
		$a_01_19 = {45 67 64 63 70 68 68 33 32 4e 70 6d 69 } //01 00  Egdcphh32Npmi
		$a_01_20 = {4c 67 74 69 70 51 74 77 70 } //01 00  LgtipQtwp
		$a_01_21 = {52 70 69 58 64 6f 6a 77 70 51 74 77 70 4e 61 78 70 41 } //00 00  RpiXdojwpQtwpNaxpA
	condition:
		any of ($a_*)
 
}