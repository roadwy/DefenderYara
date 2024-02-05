
rule Backdoor_Win32_Netbot_D{
	meta:
		description = "Backdoor:Win32/Netbot.D,SIGNATURE_TYPE_PEHSTR,06 00 06 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {4e 42 56 69 70 2e 64 6c 6c 00 } //02 00 
		$a_01_1 = {8a 08 32 ca 02 ca 88 08 40 4e 75 f4 } //02 00 
		$a_01_2 = {43 41 4f 4e 49 4d 41 44 45 53 48 41 57 4f 00 } //01 00 
		$a_01_3 = {52 75 6e 55 6e 69 6e 73 74 61 6c 6c 00 } //01 00 
		$a_01_4 = {4b 69 6c 6c 20 59 6f 75 00 } //00 00 
	condition:
		any of ($a_*)
 
}