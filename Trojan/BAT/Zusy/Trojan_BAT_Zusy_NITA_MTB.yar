
rule Trojan_BAT_Zusy_NITA_MTB{
	meta:
		description = "Trojan:BAT/Zusy.NITA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 08 00 00 "
		
	strings :
		$a_01_0 = {13 1b 11 1b 14 6f 02 00 00 2b 26 06 6f 74 00 00 06 2d 10 11 1c 7b 5b 00 00 04 1f 64 6f 1a 01 00 0a 2c e8 11 05 6f 1b 01 00 0a 11 05 6f 1c 01 00 0a 6f 1d 01 00 0a 1b 33 1d 11 1c 7b 5a 00 00 04 11 05 6f 1c 01 00 0a 6f 1e 01 00 0a 6f e6 00 00 0a 6f e7 00 00 0a de 0c } //2
		$a_01_1 = {17 28 d0 00 00 0a 0b 12 01 28 d1 00 00 0a 1f 0d 33 07 28 d2 00 00 0a 2b 4f 12 01 28 d1 00 00 0a 1e 33 23 06 6f d3 00 00 0a 16 31 d4 06 06 6f d3 00 00 0a 17 59 6f d4 00 00 0a 72 49 02 00 70 28 d5 00 00 0a 2b ba 12 01 28 d6 00 00 0a 2c b1 06 12 01 28 d6 00 00 0a 6f ce 00 00 0a 72 51 02 00 70 28 d5 00 00 0a 2b 98 } //1
		$a_01_2 = {53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 50 6f 77 65 72 53 68 65 6c 6c } //1 Start-Process PowerShell
		$a_01_3 = {45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 } //1 ExecutionPolicy Bypass
		$a_01_4 = {55 53 45 52 4e 41 4d 45 5f 54 41 52 47 45 54 5f 43 52 45 44 45 4e 54 49 41 4c 53 } //1 USERNAME_TARGET_CREDENTIALS
		$a_01_5 = {73 65 74 5f 56 69 72 74 75 61 6c 4b 65 79 43 6f 64 65 } //1 set_VirtualKeyCode
		$a_01_6 = {73 65 74 5f 43 6f 6e 74 72 6f 6c 4b 65 79 53 74 61 74 65 } //1 set_ControlKeyState
		$a_01_7 = {50 72 6f 6d 70 74 46 6f 72 50 61 73 73 77 6f 72 64 } //1 PromptForPassword
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=9
 
}