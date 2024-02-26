
rule Trojan_Win32_VBObfuse_SY_MTB{
	meta:
		description = "Trojan:Win32/VBObfuse.SY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 00 59 00 69 00 57 00 37 00 72 00 6e 00 42 00 4d 00 52 00 65 00 55 00 72 00 70 00 62 00 79 00 6b 00 79 00 41 00 56 00 7a 00 56 00 31 00 30 00 31 00 } //01 00  RYiW7rnBMReUrpbykyAVzV101
		$a_01_1 = {45 6b 73 61 6d 31 } //01 00  Eksam1
		$a_01_2 = {53 74 69 6b 6c 61 36 } //01 00  Stikla6
		$a_01_3 = {53 65 6b 73 74 65 6e 61 61 72 37 } //00 00  Sekstenaar7
	condition:
		any of ($a_*)
 
}