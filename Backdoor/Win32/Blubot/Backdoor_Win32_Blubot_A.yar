
rule Backdoor_Win32_Blubot_A{
	meta:
		description = "Backdoor:Win32/Blubot.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {44 6f 53 41 74 74 61 63 6b } //1 DoSAttack
		$a_00_1 = {4d 00 43 00 42 00 4f 00 54 00 } //1 MCBOT
		$a_01_2 = {48 54 54 50 50 61 63 6b 65 72 } //1 HTTPPacker
		$a_01_3 = {42 6c 75 65 5f 42 6f 74 6e 65 74 } //1 Blue_Botnet
		$a_00_4 = {5c 00 73 00 79 00 73 00 66 00 69 00 6c 00 65 00 2e 00 65 00 78 00 65 00 } //1 \sysfile.exe
		$a_00_5 = {62 00 6f 00 74 00 6c 00 6f 00 67 00 67 00 65 00 72 00 2e 00 70 00 68 00 70 00 } //1 botlogger.php
		$a_00_6 = {70 00 72 00 76 00 5f 00 61 00 74 00 74 00 61 00 63 00 6b 00 } //1 prv_attack
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=5
 
}