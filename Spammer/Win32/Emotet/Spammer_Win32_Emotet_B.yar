
rule Spammer_Win32_Emotet_B{
	meta:
		description = "Spammer:Win32/Emotet.B,SIGNATURE_TYPE_PEHSTR_EXT,79 00 79 00 04 00 00 64 00 "
		
	strings :
		$a_01_0 = {6d 79 20 68 75 67 65 20 65 6e 74 72 6f 70 79 20 66 6f 72 20 72 6e 67 2e 2e 20 62 6c 61 68 } //0a 00  my huge entropy for rng.. blah
		$a_01_1 = {22 00 25 00 73 00 22 00 20 00 2f 00 63 00 20 00 22 00 25 00 73 00 22 00 } //0a 00  "%s" /c "%s"
		$a_01_2 = {43 00 6f 00 6d 00 53 00 70 00 65 00 63 00 } //01 00  ComSpec
		$a_01_3 = {25 66 72 6f 6d 5f 65 6d 61 69 6c 25 } //00 00  %from_email%
	condition:
		any of ($a_*)
 
}