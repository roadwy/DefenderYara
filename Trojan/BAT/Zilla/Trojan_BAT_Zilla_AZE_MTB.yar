
rule Trojan_BAT_Zilla_AZE_MTB{
	meta:
		description = "Trojan:BAT/Zilla.AZE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0d 00 00 "
		
	strings :
		$a_01_0 = {6e 73 74 6c 69 63 68 65 49 6e 74 65 6c 6c 69 67 65 6e 7a 63 79 7a 49 42 30 } //1 nstlicheIntelligenzcyzIB0
		$a_01_1 = {69 6e 74 65 6c 6c 69 67 65 6e 63 65 63 45 43 4d 42 30 } //1 intelligencecECMB0
		$a_01_2 = {64 65 6d 6f 73 74 72 61 72 58 52 48 4e 42 30 } //1 demostrarXRHNB0
		$a_01_3 = {70 72 65 64 6f 6d 69 6e 61 6e 74 59 5a 67 4f 42 30 } //1 predominantYZgOB0
		$a_01_4 = {4c 6f 67 69 6b 67 61 74 74 65 72 76 71 64 53 42 30 } //1 LogikgattervqdSB0
		$a_01_5 = {65 6d 65 72 67 65 44 4e 77 55 42 30 } //1 emergeDNwUB0
		$a_01_6 = {70 65 72 66 6f 72 6d 6a 59 4e 56 42 30 } //1 performjYNVB0
		$a_01_7 = {73 70 65 6c 6c 4b 4f 71 56 42 30 } //1 spellKOqVB0
		$a_01_8 = {63 61 6c 6d 65 44 63 50 57 42 30 } //1 calmeDcPWB0
		$a_01_9 = {6d 6f 65 6c 6c 65 75 78 79 50 6f 58 42 30 } //1 moelleuxyPoXB0
		$a_01_10 = {62 61 6e 6b 69 6e 67 63 58 77 62 42 30 } //1 bankingcXwbB0
		$a_01_11 = {44 72 6f 68 6e 65 58 77 43 68 42 30 } //1 DrohneXwChB0
		$a_01_12 = {69 6e 63 65 6e 74 69 76 65 58 65 55 68 42 30 } //1 incentiveXeUhB0
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=13
 
}