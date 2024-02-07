
rule TrojanSpy_BAT_Rozena_MA_MTB{
	meta:
		description = "TrojanSpy:BAT/Rozena.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0e 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 00 79 00 49 00 70 00 44 00 51 00 70 00 39 00 44 00 51 00 6f 00 3d 00 } //01 00  TyIpDQp9DQo=
		$a_01_1 = {2d 00 77 00 68 00 61 00 74 00 74 00 } //01 00  -whatt
		$a_01_2 = {52 65 70 6c 61 63 65 } //01 00  Replace
		$a_01_3 = {2d 00 65 00 78 00 74 00 64 00 75 00 6d 00 6d 00 74 00 } //01 00  -extdummt
		$a_01_4 = {2d 00 64 00 65 00 62 00 75 00 67 00 } //01 00  -debug
		$a_01_5 = {2d 00 7a 00 7a 00 78 00 74 00 72 00 61 00 63 00 74 00 } //01 00  -zzxtract
		$a_01_6 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_7 = {43 72 65 64 55 49 50 72 6f 6d 70 74 46 6f 72 43 72 65 64 65 6e 74 69 61 6c 73 } //01 00  CredUIPromptForCredentials
		$a_01_8 = {50 72 6f 6d 70 74 46 6f 72 50 61 73 73 77 6f 72 64 } //01 00  PromptForPassword
		$a_01_9 = {67 65 74 50 61 73 73 77 6f 72 64 } //01 00  getPassword
		$a_01_10 = {47 65 74 43 68 61 72 46 72 6f 6d 4b 65 79 73 } //01 00  GetCharFromKeys
		$a_01_11 = {43 72 65 64 65 6e 74 69 61 6c 5f 46 6f 72 6d } //01 00  Credential_Form
		$a_01_12 = {4b 65 79 62 6f 61 72 64 5f 46 6f 72 6d 5f 4b 65 79 55 70 } //01 00  Keyboard_Form_KeyUp
		$a_01_13 = {73 65 74 5f 56 69 72 74 75 61 6c 4b 65 79 43 6f 64 65 } //00 00  set_VirtualKeyCode
	condition:
		any of ($a_*)
 
}