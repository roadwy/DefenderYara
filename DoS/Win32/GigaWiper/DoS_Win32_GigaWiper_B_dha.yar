
rule DoS_Win32_GigaWiper_B_dha{
	meta:
		description = "DoS:Win32/GigaWiper.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {50 61 73 73 20 54 69 6d 65 20 74 6f 6f 6b 3a 20 25 73 } //1 Pass Time took: %s
		$a_01_1 = {46 61 69 6c 65 64 20 74 6f 20 6f 70 65 6e 20 64 72 69 76 65 20 25 73 3a 20 25 76 } //1 Failed to open drive %s: %v
		$a_01_2 = {42 79 74 65 73 20 74 6f 20 64 69 73 6b 2e 20 63 6f 75 6e 74 65 72 3a } //1 Bytes to disk. counter:
		$a_01_3 = {50 61 73 73 20 25 64 20 63 6f 6d 70 6c 65 74 65 28 52 61 6e 64 6f 6d 29 2e } //1 Pass %d complete(Random).
		$a_01_4 = {45 72 72 6f 72 20 64 75 72 69 6e 67 20 77 72 69 74 65 3a 20 25 76 } //1 Error during write: %v
		$a_01_5 = {46 61 69 6c 65 64 20 74 6f 20 67 65 74 20 64 69 73 6b 20 73 69 7a 65 3a 20 25 76 } //1 Failed to get disk size: %v
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}