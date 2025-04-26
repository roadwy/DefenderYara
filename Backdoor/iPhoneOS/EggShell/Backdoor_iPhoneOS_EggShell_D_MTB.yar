
rule Backdoor_iPhoneOS_EggShell_D_MTB{
	meta:
		description = "Backdoor:iPhoneOS/EggShell.D!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {45 67 67 53 68 65 6c 6c 2f 73 6f 75 72 63 65 2d 65 73 70 6c 6f 73 78 2f 65 73 70 6c 6f 73 78 2f 65 73 70 6c 2e 68 } //2 EggShell/source-esplosx/esplosx/espl.h
		$a_00_1 = {2f 74 6d 70 2f 2e 61 76 61 74 6d 70 } //1 /tmp/.avatmp
		$a_00_2 = {65 73 70 6c 20 64 64 6f 73 3a } //1 espl ddos:
		$a_00_3 = {64 65 63 72 79 70 74 20 66 69 6c 65 2e 61 65 73 20 70 61 73 73 77 6f 72 64 31 32 33 34 } //1 decrypt file.aes password1234
		$a_00_4 = {67 65 74 63 61 70 74 75 72 65 64 65 76 69 63 65 } //1 getcapturedevice
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}