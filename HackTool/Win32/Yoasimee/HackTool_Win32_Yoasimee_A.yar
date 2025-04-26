
rule HackTool_Win32_Yoasimee_A{
	meta:
		description = "HackTool:Win32/Yoasimee.A,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {50 00 6c 00 65 00 61 00 73 00 65 00 20 00 65 00 6e 00 61 00 62 00 6c 00 65 00 20 00 55 00 41 00 43 00 20 00 66 00 6f 00 72 00 20 00 74 00 68 00 69 00 73 00 20 00 61 00 63 00 63 00 6f 00 75 00 6e 00 74 00 2e 00 } //1 Please enable UAC for this account.
		$a_01_1 = {41 00 64 00 6d 00 69 00 6e 00 20 00 61 00 63 00 63 00 6f 00 75 00 6e 00 74 00 20 00 77 00 69 00 74 00 68 00 20 00 6c 00 69 00 6d 00 69 00 74 00 65 00 64 00 20 00 74 00 6f 00 6b 00 65 00 6e 00 20 00 72 00 65 00 71 00 75 00 69 00 72 00 65 00 64 00 2e 00 } //1 Admin account with limited token required.
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}