
rule Trojan_BAT_BadJoke_MA_MTB{
	meta:
		description = "Trojan:BAT/BadJoke.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {43 00 61 00 6e 00 27 00 74 00 20 00 63 00 6c 00 6f 00 73 00 65 00 20 00 6d 00 65 00 20 00 3b 00 29 00 } //1 Can't close me ;)
		$a_01_1 = {74 72 6f 6c 6c } //1 troll
		$a_01_2 = {74 69 6d 65 72 31 5f 54 69 63 6b } //1 timer1_Tick
		$a_01_3 = {53 65 74 44 65 73 6b 74 6f 70 4c 6f 63 61 74 69 6f 6e } //1 SetDesktopLocation
		$a_01_4 = {61 30 66 30 62 35 63 65 2d 32 37 64 61 2d 34 31 34 33 2d 62 32 61 65 2d 34 62 37 31 39 37 64 66 34 36 61 37 } //1 a0f0b5ce-27da-4143-b2ae-4b7197df46a7
		$a_01_5 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_6 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}