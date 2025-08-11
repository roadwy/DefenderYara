
rule DoS_Win32_GigaWiper_A_dha{
	meta:
		description = "DoS:Win32/GigaWiper.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {25 73 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 } //1 %s\Windows\System32
		$a_01_1 = {66 61 69 6c 65 64 20 74 6f 20 63 6c 65 61 72 20 70 61 72 74 69 74 69 6f 6e 73 3a 20 25 76 } //1 failed to clear partitions: %v
		$a_01_2 = {50 61 72 74 69 74 69 6f 6e 73 20 72 65 6d 6f 76 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 2e } //1 Partitions removed successfully.
		$a_01_3 = {53 74 61 72 74 69 6e 67 20 70 61 73 73 20 25 64 2e 2e 2e } //1 Starting pass %d...
		$a_01_4 = {66 61 69 6c 65 64 20 74 6f 20 77 72 69 74 65 20 74 6f 20 64 69 73 6b 3a } //1 failed to write to disk:
		$a_01_5 = {45 72 72 6f 72 20 6f 6e 20 72 65 62 6f 6f 74 69 6e 67 3a } //1 Error on rebooting:
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}