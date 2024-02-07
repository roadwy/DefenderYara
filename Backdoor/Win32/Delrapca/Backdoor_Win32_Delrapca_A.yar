
rule Backdoor_Win32_Delrapca_A{
	meta:
		description = "Backdoor:Win32/Delrapca.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {80 39 00 75 06 8b 0d 90 01 04 8a 11 80 c2 17 30 10 41 40 4e 75 e9 90 00 } //01 00 
		$a_01_1 = {0f b6 86 96 01 00 00 50 0f b6 86 95 01 00 00 50 0f b6 86 94 01 00 00 } //01 00 
		$a_01_2 = {3c 62 72 3e 20 53 79 73 40 55 73 65 72 20 3a 20 25 73 40 25 73 20 28 25 73 29 } //01 00  <br> Sys@User : %s@%s (%s)
		$a_01_3 = {25 73 3f 61 72 67 31 3d 25 73 26 61 72 67 32 3d 25 73 26 61 72 67 33 3d 25 73 } //00 00  %s?arg1=%s&arg2=%s&arg3=%s
	condition:
		any of ($a_*)
 
}