
rule Trojan_Win32_SysWiper_GK_MTB{
	meta:
		description = "Trojan:Win32/SysWiper.GK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,46 00 46 00 07 00 00 "
		
	strings :
		$a_01_0 = {4e 6f 74 20 72 75 6e 6e 69 6e 67 20 77 69 74 68 20 61 64 6d 69 6e 20 70 72 69 76 69 6c 65 67 65 73 2e } //10 Not running with admin privileges.
		$a_01_1 = {52 75 6e 6e 69 6e 67 20 77 69 74 68 20 61 64 6d 69 6e 20 70 72 69 76 69 6c 65 67 65 73 2e } //10 Running with admin privileges.
		$a_01_2 = {53 74 61 63 6b 20 6d 65 6d 6f 72 79 20 77 61 73 20 63 6f 72 72 75 70 74 65 64 } //10 Stack memory was corrupted
		$a_01_3 = {41 20 6c 6f 63 61 6c 20 76 61 72 69 61 62 6c 65 20 77 61 73 20 75 73 65 64 20 62 65 66 6f 72 65 20 69 74 20 77 61 73 20 69 6e 69 74 69 61 6c 69 7a 65 64 } //10 A local variable was used before it was initialized
		$a_01_4 = {63 61 75 73 69 6e 67 20 6c 6f 73 73 20 6f 66 20 64 61 74 61 } //10 causing loss of data
		$a_00_5 = {5c 00 47 00 4c 00 4f 00 42 00 41 00 4c 00 52 00 4f 00 4f 00 54 00 } //10 \GLOBALROOT
		$a_00_6 = {55 00 6e 00 61 00 62 00 6c 00 65 00 20 00 74 00 6f 00 20 00 64 00 69 00 73 00 70 00 6c 00 61 00 79 00 20 00 52 00 54 00 43 00 20 00 4d 00 65 00 73 00 73 00 61 00 67 00 65 00 } //10 Unable to display RTC Message
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_00_5  & 1)*10+(#a_00_6  & 1)*10) >=70
 
}