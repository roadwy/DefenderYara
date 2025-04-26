
rule Trojan_BAT_Formbook_AMP_MTB{
	meta:
		description = "Trojan:BAT/Formbook.AMP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_81_0 = {68 73 78 69 4a 6f 4c 4d 70 6e 42 4a 70 45 4e 68 65 58 4f 76 52 4c 46 5a 42 47 68 7a } //1 hsxiJoLMpnBJpENheXOvRLFZBGhz
		$a_81_1 = {67 55 4d 6d 59 68 52 43 78 75 79 6d 61 43 70 79 58 72 75 45 4b 7a 6e 73 72 70 4b 70 } //1 gUMmYhRCxuymaCpyXruEKznsrpKp
		$a_81_2 = {64 41 6d 61 6c 65 4e 68 73 6b 65 48 6c 49 43 6f 65 67 4c 41 4b 52 6e 4d 4c 57 54 67 41 } //1 dAmaleNhskeHlICoegLAKRnMLWTgA
		$a_81_3 = {56 54 7a 4a 42 70 77 63 65 59 74 6e 75 79 46 58 52 54 71 50 4e 62 47 6d 71 4f 59 4f } //1 VTzJBpwceYtnuyFXRTqPNbGmqOYO
		$a_81_4 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //1 DebuggerHiddenAttribute
		$a_81_5 = {67 55 4d 6d 59 68 52 43 78 75 79 6d 61 43 70 79 58 72 75 45 4b 7a 6e 73 72 70 4b 70 2e 72 65 73 6f 75 72 63 65 73 } //1 gUMmYhRCxuymaCpyXruEKznsrpKp.resources
		$a_01_6 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 74 00 65 00 6e 00 73 00 6f 00 72 00 66 00 6c 00 6f 00 77 00 2e 00 6f 00 72 00 67 00 2f 00 64 00 6f 00 63 00 73 00 2f 00 } //1 http://tensorflow.org/docs/
		$a_81_7 = {53 54 41 54 68 72 65 61 64 41 74 74 72 69 62 75 74 65 } //1 STAThreadAttribute
		$a_81_8 = {52 65 76 65 72 73 65 } //1 Reverse
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_01_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=9
 
}