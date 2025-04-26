
rule Trojan_Win32_Qbot_NEAA_MTB{
	meta:
		description = "Trojan:Win32/Qbot.NEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1c 00 1c 00 0b 00 00 "
		
	strings :
		$a_01_0 = {76 75 4b 46 53 62 6c 6a 50 4b 4b 4e 6b 79 } //5 vuKFSbljPKKNky
		$a_01_1 = {44 4b 65 53 46 59 7a 64 44 7a 45 78 47 6f 62 61 72 6f 50 43 54 65 5a 73 } //5 DKeSFYzdDzExGobaroPCTeZs
		$a_01_2 = {6c 65 70 74 6f 70 72 6f 73 6f 70 79 } //2 leptoprosopy
		$a_01_3 = {75 6e 72 65 63 61 6c 6c 61 62 6c 79 } //2 unrecallably
		$a_01_4 = {61 6e 74 69 63 68 72 69 73 74 69 61 6e } //2 antichristian
		$a_01_5 = {74 65 6c 65 64 65 6e 64 72 6f 6e } //2 teledendron
		$a_01_6 = {64 65 6a 65 72 61 74 69 6f 6e } //2 dejeration
		$a_01_7 = {73 69 6e 67 69 6e 67 6c 79 } //2 singingly
		$a_01_8 = {50 00 69 00 72 00 69 00 66 00 6f 00 72 00 6d 00 20 00 4c 00 74 00 64 00 } //2 Piriform Ltd
		$a_01_9 = {32 00 2c 00 20 00 32 00 39 00 2c 00 20 00 30 00 2c 00 20 00 31 00 31 00 31 00 31 00 } //2 2, 29, 0, 1111
		$a_01_10 = {63 00 63 00 6c 00 65 00 61 00 6e 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //2 ccleaner.exe
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2+(#a_01_8  & 1)*2+(#a_01_9  & 1)*2+(#a_01_10  & 1)*2) >=28
 
}