
rule Trojan_Win32_Qakbot_FL_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.FL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 49 6e 73 74 61 6c 6c } //01 00 
		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00 
		$a_01_2 = {4c 41 7a 58 45 67 } //01 00 
		$a_01_3 = {4e 50 4b 4a 42 76 39 6c 71 } //01 00 
		$a_01_4 = {54 4f 64 51 37 36 30 32 } //01 00 
		$a_01_5 = {43 6f 6e 6e 65 63 74 4e 61 6d 65 64 50 69 70 65 } //01 00 
		$a_01_6 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //00 00 
	condition:
		any of ($a_*)
 
}