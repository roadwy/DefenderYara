
rule Backdoor_Win32_Botgor_A{
	meta:
		description = "Backdoor:Win32/Botgor.A,SIGNATURE_TYPE_PEHSTR,15 00 15 00 0b 00 00 "
		
	strings :
		$a_01_0 = {62 6f 74 73 5f 63 6f 6e 74 72 6f 6c 6c 65 72 2e 70 68 70 } //5 bots_controller.php
		$a_01_1 = {67 75 69 64 5f 62 6f 74 3d } //5 guid_bot=
		$a_01_2 = {56 69 72 75 73 20 69 73 20 73 74 61 72 74 65 64 21 } //5 Virus is started!
		$a_01_3 = {45 58 45 20 69 73 20 73 75 63 63 65 73 73 66 75 6c 6c 79 20 69 6e 66 65 63 74 65 64 } //5 EXE is successfully infected
		$a_01_4 = {76 69 61 67 72 61 } //1 viagra
		$a_01_5 = {6d 61 72 69 68 75 61 6e 61 } //1 marihuana
		$a_01_6 = {65 72 6f 74 69 63 } //1 erotic
		$a_01_7 = {2a 70 65 6e 69 73 2a } //1 *penis*
		$a_01_8 = {2a 73 65 78 2a } //1 *sex*
		$a_01_9 = {2a 70 6f 72 6e 6f 2a } //1 *porno*
		$a_01_10 = {2a 70 75 72 63 68 61 73 65 2a } //1 *purchase*
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=21
 
}