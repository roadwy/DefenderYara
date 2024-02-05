
rule Backdoor_Win32_Spycos_D{
	meta:
		description = "Backdoor:Win32/Spycos.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {59 50 78 35 6d 49 4a 41 54 6b 64 66 71 37 43 5a 44 46 6c 79 4c 77 3d 3d } //01 00 
		$a_01_1 = {49 4d 4e 6c 33 71 4e 70 6e 75 47 73 65 64 62 31 71 65 79 6a 2f 79 4d 39 61 4d 4f 66 4a 31 58 6f 31 31 61 45 76 70 54 76 30 6c 6b 3d } //01 00 
		$a_03_2 = {63 6c 69 65 6e 74 65 3d 90 02 20 6d 65 6e 73 61 67 65 6d 3d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}