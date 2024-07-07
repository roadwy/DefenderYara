
rule HackTool_BAT_Windissec_L_MTB{
	meta:
		description = "HackTool:BAT/Windissec.L!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_03_0 = {61 20 f4 1c a1 30 07 5c 0b 5f 07 20 00 90 01 03 58 fe 03 0c 07 20 10 90 01 03 61 5f 07 20 00 90 01 03 61 fe 03 20 bd 90 01 03 07 61 0b 13 04 07 20 fd 7c 0f 21 5f 90 00 } //5
		$a_80_1 = {44 69 73 61 62 6c 65 20 79 6f 75 72 20 41 6e 74 69 2d 56 69 72 75 73 } //Disable your Anti-Virus  1
		$a_80_2 = {73 63 20 64 65 6c 65 74 65 20 66 61 63 65 69 74 } //sc delete faceit  1
		$a_80_3 = {72 6f 6f 74 5c 63 69 6d 76 32 5c 73 65 63 75 72 69 74 79 5c 4d 69 63 72 6f 73 6f 66 74 54 70 6d } //root\cimv2\security\MicrosoftTpm  1
		$a_80_4 = {48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 5c 53 4f 46 54 57 41 52 45 5c 50 6f 6c 69 63 69 65 73 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 57 69 6e 64 6f 77 73 55 70 64 61 74 65 5c 41 55 } //HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU  1
	condition:
		((#a_03_0  & 1)*5+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=9
 
}