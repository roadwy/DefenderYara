
rule Backdoor_Win32_Kawpfuni_A{
	meta:
		description = "Backdoor:Win32/Kawpfuni.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 54 01 ff 48 f6 d2 88 14 01 75 f4 } //01 00 
		$a_01_1 = {57 61 6b 65 75 70 20 74 69 6d 65 20 3d 20 32 30 25 30 32 64 3a 25 64 3a 25 64 0d 0a 5b 57 57 57 5d 0d 0a 25 73 0d 0a 5b 49 6e 66 65 63 74 5d 0d 0a 25 73 } //00 00 
	condition:
		any of ($a_*)
 
}