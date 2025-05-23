
rule TrojanSpy_BAT_Stealer_MC_MTB{
	meta:
		description = "TrojanSpy:BAT/Stealer.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0d 00 00 "
		
	strings :
		$a_01_0 = {4a 00 61 00 59 00 47 00 56 00 79 00 62 00 79 00 49 00 70 00 44 00 51 00 70 00 39 00 44 00 51 00 6f 00 3d 00 } //1 JaYGVybyIpDQp9DQo=
		$a_01_1 = {2d 00 77 00 68 00 61 00 74 00 74 00 } //1 -whatt
		$a_01_2 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_01_3 = {2d 00 65 00 78 00 74 00 64 00 75 00 6d 00 6d 00 74 00 } //1 -extdummt
		$a_01_4 = {2d 00 7a 00 7a 00 78 00 74 00 72 00 61 00 63 00 74 00 } //1 -zzxtract
		$a_01_5 = {2d 00 64 00 65 00 62 00 75 00 67 00 } //1 -debug
		$a_01_6 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_7 = {50 72 6f 6d 70 74 46 6f 72 50 61 73 73 77 6f 72 64 } //1 PromptForPassword
		$a_01_8 = {67 65 74 50 61 73 73 77 6f 72 64 } //1 getPassword
		$a_01_9 = {43 72 65 64 65 6e 74 69 61 6c 5f 46 6f 72 6d } //1 Credential_Form
		$a_01_10 = {55 53 45 52 4e 41 4d 45 5f 54 41 52 47 45 54 5f 43 52 45 44 45 4e 54 49 41 4c 53 } //1 USERNAME_TARGET_CREDENTIALS
		$a_01_11 = {67 65 74 5f 43 6f 6e 74 72 6f 6c 4b 65 79 53 74 61 74 65 } //1 get_ControlKeyState
		$a_01_12 = {50 6f 77 65 72 53 68 65 6c 6c } //1 PowerShell
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=13
 
}