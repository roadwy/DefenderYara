
rule TrojanSpy_BAT_Stealer_MD_MTB{
	meta:
		description = "TrojanSpy:BAT/Stealer.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {2d 00 77 00 68 00 61 00 74 00 74 00 } //01 00  -whatt
		$a_01_1 = {2d 00 65 00 78 00 74 00 64 00 75 00 6d 00 6d 00 74 00 } //01 00  -extdummt
		$a_01_2 = {2d 00 7a 00 7a 00 78 00 74 00 72 00 61 00 63 00 74 00 } //01 00  -zzxtract
		$a_01_3 = {2d 00 64 00 65 00 62 00 75 00 67 00 } //01 00  -debug
		$a_01_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_5 = {49 00 77 00 30 00 4b 00 49 00 79 00 42 00 44 00 54 00 30 00 35 00 47 00 53 00 55 00 64 00 } //01 00  Iw0KIyBDT05GSUd
		$a_01_6 = {50 72 6f 6d 70 74 46 6f 72 50 61 73 73 77 6f 72 64 } //01 00  PromptForPassword
		$a_01_7 = {4b 65 79 62 6f 61 72 64 5f 46 6f 72 6d 5f 4b 65 79 44 6f 77 6e } //01 00  Keyboard_Form_KeyDown
		$a_01_8 = {43 72 65 64 65 6e 74 69 61 6c 5f 46 6f 72 6d } //00 00  Credential_Form
	condition:
		any of ($a_*)
 
}