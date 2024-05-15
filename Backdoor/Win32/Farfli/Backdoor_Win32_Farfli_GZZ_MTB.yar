
rule Backdoor_Win32_Farfli_GZZ_MTB{
	meta:
		description = "Backdoor:Win32/Farfli.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {4d 34 2c 6b 78 48 38 } //05 00  M4,kxH8
		$a_01_1 = {9d 10 fb 22 5a 61 01 29 24 37 4c 10 59 52 3b f0 71 ed } //00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Farfli_GZZ_MTB_2{
	meta:
		description = "Backdoor:Win32/Farfli.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8d 64 24 00 80 b4 05 90 01 04 d7 40 3d c0 67 0f 00 75 90 00 } //01 00 
		$a_01_1 = {5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 75 70 64 61 74 65 2e 65 78 65 } //01 00  \ProgramData\update.exe
		$a_01_2 = {5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 6a 66 64 73 2e 74 78 74 } //00 00  \ProgramData\jfds.txt
	condition:
		any of ($a_*)
 
}