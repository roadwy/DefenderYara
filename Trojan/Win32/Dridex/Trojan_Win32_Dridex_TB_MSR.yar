
rule Trojan_Win32_Dridex_TB_MSR{
	meta:
		description = "Trojan:Win32/Dridex.TB!MSR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 00 6f 00 62 00 65 00 72 00 74 00 6d 00 61 00 6a 00 6f 00 72 00 2e 00 6d 00 69 00 6e 00 6f 00 72 00 44 00 6f 00 69 00 6e 00 74 00 65 00 72 00 61 00 63 00 74 00 69 00 76 00 69 00 74 00 79 00 74 00 6f 00 56 00 62 00 65 00 4a 00 } //01 00  robertmajor.minorDointeractivitytoVbeJ
		$a_01_1 = {74 6f 74 68 69 73 42 61 73 65 64 4e 50 41 50 49 76 79 } //01 00  tothisBasedNPAPIvy
		$a_01_2 = {54 68 65 4a 47 77 65 65 6b 73 45 75 72 6f 70 65 61 6e 6f 77 65 62 73 69 74 65 67 61 72 62 61 67 65 } //01 00  TheJGweeksEuropeanowebsitegarbage
		$a_01_3 = {47 00 76 00 6f 00 61 00 6e 00 64 00 69 00 6e 00 32 00 30 00 31 00 38 00 2c 00 59 00 62 00 6f 00 78 00 6a 00 61 00 63 00 6b 00 69 00 65 00 59 00 } //01 00  Gvoandin2018,YboxjackieY
		$a_01_4 = {42 00 72 00 69 00 6e 00 47 00 6f 00 6f 00 67 00 6c 00 65 00 69 00 } //00 00  BrinGooglei
	condition:
		any of ($a_*)
 
}