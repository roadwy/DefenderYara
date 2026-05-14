
rule DoS_Win64_WprReindeerBebop_C_dha{
	meta:
		description = "DoS:Win64/WprReindeerBebop.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {46 61 69 6c 65 64 20 74 6f 20 6f 70 65 6e 20 64 69 73 6b 2e 20 45 72 72 6f 72 3a } //1 Failed to open disk. Error:
		$a_01_1 = {49 4f 43 54 4c 20 66 61 69 6c 65 64 2e 20 45 72 72 6f 72 3a } //1 IOCTL failed. Error:
		$a_01_2 = {44 72 69 76 65 20 6c 61 79 6f 75 74 20 64 65 6c 65 74 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 2e } //1 Drive layout deleted successfully.
		$a_01_3 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 25 64 } //1 \\.\PhysicalDrive%d
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}