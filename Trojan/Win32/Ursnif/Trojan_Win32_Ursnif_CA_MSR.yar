
rule Trojan_Win32_Ursnif_CA_MSR{
	meta:
		description = "Trojan:Win32/Ursnif.CA!MSR,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 0a 00 00 02 00 "
		
	strings :
		$a_01_0 = {41 4b 71 46 4e 4f 67 78 62 56 76 67 4a 63 59 72 53 44 58 } //02 00  AKqFNOgxbVvgJcYrSDX
		$a_01_1 = {41 69 77 51 47 4c 72 74 5a 48 58 55 6a 47 64 41 } //02 00  AiwQGLrtZHXUjGdA
		$a_01_2 = {42 4f 68 72 4a 69 6e 7a 72 6d 59 51 } //02 00  BOhrJinzrmYQ
		$a_01_3 = {43 64 67 74 44 6f 70 41 6e 45 5a 6f 61 6e 62 4e 47 4a 67 62 } //02 00  CdgtDopAnEZoanbNGJgb
		$a_01_4 = {47 4e 72 49 76 65 75 65 43 72 6e 4c 55 4b 48 49 6a 4f } //02 00  GNrIveueCrnLUKHIjO
		$a_01_5 = {48 67 4c 7a 50 79 42 6f 4c 4e 4c 52 76 49 64 52 51 67 51 64 4a } //02 00  HgLzPyBoLNLRvIdRQgQdJ
		$a_01_6 = {4e 6c 5a 5a 42 47 4f 76 65 6e 70 53 46 48 } //02 00  NlZZBGOvenpSFH
		$a_01_7 = {4f 46 58 74 43 5a 52 76 66 61 54 4b 48 77 76 7a 41 } //02 00  OFXtCZRvfaTKHwvzA
		$a_01_8 = {4f 73 46 4f 49 6f 68 56 6c 71 53 50 50 72 4b 45 63 59 4c } //02 00  OsFOIohVlqSPPrKEcYL
		$a_01_9 = {50 54 59 4a 63 64 6d 48 4e 50 42 47 77 6f 77 50 46 44 6e 78 63 } //00 00  PTYJcdmHNPBGwowPFDnxc
	condition:
		any of ($a_*)
 
}