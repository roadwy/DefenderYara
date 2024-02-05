
rule Backdoor_Win32_Vonost_A{
	meta:
		description = "Backdoor:Win32/Vonost.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {c6 85 cb 00 00 00 68 c6 85 cc 00 00 00 2d c6 85 cd 00 00 00 63 c6 85 ce 00 00 00 6e c6 85 cf 00 00 00 0d } //05 00 
		$a_01_1 = {7c 58 69 61 6e 43 68 65 6e 67 44 65 6c 61 79 7c 00 } //05 00 
		$a_01_2 = {7c 47 65 74 5a 68 75 61 6e 67 54 61 69 7c 00 } //01 00 
		$a_01_3 = {73 76 6f 6e 6f 73 74 2e 65 78 65 00 } //01 00 
		$a_01_4 = {7a 68 75 64 6f 6e 67 66 61 6e 67 79 75 2e 65 78 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}