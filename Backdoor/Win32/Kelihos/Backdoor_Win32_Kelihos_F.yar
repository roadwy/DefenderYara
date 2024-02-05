
rule Backdoor_Win32_Kelihos_F{
	meta:
		description = "Backdoor:Win32/Kelihos.F,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {5b 50 52 4f 58 59 5f 53 4f 43 4b 45 54 5f 57 4f 52 4b 45 52 5d } //01 00 
		$a_01_1 = {66 69 6e 64 5f 61 6e 64 5f 6b 69 6c 6c 5f 6f 6c 64 5f 63 6c 69 65 6e 74 73 } //01 00 
		$a_01_2 = {5c 42 69 74 63 6f 69 6e 5c 77 61 6c 6c 65 74 2e 64 61 74 } //0a 00 
		$a_01_3 = {4d 49 49 42 43 41 4b 43 41 51 45 41 } //00 00 
	condition:
		any of ($a_*)
 
}