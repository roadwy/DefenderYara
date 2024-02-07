
rule Backdoor_Win32_Susftp_A{
	meta:
		description = "Backdoor:Win32/Susftp.A,SIGNATURE_TYPE_PEHSTR,05 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 45 78 65 63 75 74 65 20 6f 6b 21 20 3a 2d 29 } //01 00  ShellExecute ok! :-)
		$a_01_1 = {53 74 61 72 74 20 43 6d 64 20 53 68 65 6c 6c 20 4f 4b 20 61 74 20 70 6f 72 74 3a 00 53 65 6e 64 20 62 61 63 6b 20 63 6d 64 73 68 65 6c 6c } //01 00 
		$a_01_2 = {2a 2a 2a 20 45 4e 44 20 4f 46 20 41 50 50 4c 49 43 41 54 49 4f 4e 20 2a 2a 2a } //01 00  *** END OF APPLICATION ***
		$a_01_3 = {68 74 74 70 64 6f 77 6e 6c 6f 61 64 } //01 00  httpdownload
		$a_01_4 = {63 61 74 63 68 20 53 63 72 65 65 6e 20 66 69 6e 69 73 68 65 64 2e 20 54 68 65 20 42 4d 50 20 66 69 6c 65 20 69 73 20 73 61 76 65 64 20 74 6f 20 } //00 00  catch Screen finished. The BMP file is saved to 
	condition:
		any of ($a_*)
 
}