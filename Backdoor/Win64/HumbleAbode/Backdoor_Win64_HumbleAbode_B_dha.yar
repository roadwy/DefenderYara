
rule Backdoor_Win64_HumbleAbode_B_dha{
	meta:
		description = "Backdoor:Win64/HumbleAbode.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 50 69 70 65 20 67 5f 68 43 68 69 6c 64 53 74 64 5f 4f 55 54 5f 52 64 20 26 20 67 5f 68 43 68 69 6c 64 53 74 64 5f 4f 55 54 5f 57 72 20 66 61 69 6c 65 64 21 } //1 CreatePipe g_hChildStd_OUT_Rd & g_hChildStd_OUT_Wr failed!
		$a_01_1 = {53 65 74 48 61 6e 64 6c 65 49 6e 66 6f 72 6d 61 74 69 6f 6e 20 67 5f 68 43 68 69 6c 64 53 74 64 5f 49 4e 5f 57 72 20 66 61 69 6c 65 64 21 } //1 SetHandleInformation g_hChildStd_IN_Wr failed!
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}