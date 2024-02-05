
rule Backdoor_Win32_Speadear_A{
	meta:
		description = "Backdoor:Win32/Speadear.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 53 79 73 74 65 6d 33 32 5c 73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b } //01 00 
		$a_01_1 = {73 70 64 69 72 73 2e 64 6c 6c } //01 00 
		$a_01_2 = {52 65 67 53 65 74 56 61 6c 75 65 45 78 28 53 76 63 68 6f 73 74 5c 6e 65 74 73 76 63 73 29 } //01 00 
		$a_01_3 = {49 6e 73 74 61 6c 6c 41 00 49 6e 73 74 61 6c 6c 42 00 49 6e 73 74 61 6c 6c 43 } //00 00 
	condition:
		any of ($a_*)
 
}