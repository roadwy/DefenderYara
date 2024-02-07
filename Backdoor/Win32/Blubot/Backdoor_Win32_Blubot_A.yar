
rule Backdoor_Win32_Blubot_A{
	meta:
		description = "Backdoor:Win32/Blubot.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 6f 53 41 74 74 61 63 6b } //01 00  DoSAttack
		$a_00_1 = {4d 00 43 00 42 00 4f 00 54 00 } //01 00  MCBOT
		$a_01_2 = {48 54 54 50 50 61 63 6b 65 72 } //01 00  HTTPPacker
		$a_01_3 = {42 6c 75 65 5f 42 6f 74 6e 65 74 } //01 00  Blue_Botnet
		$a_00_4 = {5c 00 73 00 79 00 73 00 66 00 69 00 6c 00 65 00 2e 00 65 00 78 00 65 00 } //01 00  \sysfile.exe
		$a_00_5 = {62 00 6f 00 74 00 6c 00 6f 00 67 00 67 00 65 00 72 00 2e 00 70 00 68 00 70 00 } //01 00  botlogger.php
		$a_00_6 = {70 00 72 00 76 00 5f 00 61 00 74 00 74 00 61 00 63 00 6b 00 } //00 00  prv_attack
		$a_00_7 = {5d 04 00 } //00 17 
	condition:
		any of ($a_*)
 
}