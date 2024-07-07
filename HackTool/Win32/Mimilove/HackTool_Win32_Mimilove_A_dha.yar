
rule HackTool_Win32_Mimilove_A_dha{
	meta:
		description = "HackTool:Win32/Mimilove.A!dha,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4c 00 53 00 41 00 53 00 52 00 56 00 20 00 43 00 72 00 65 00 64 00 65 00 6e 00 74 00 69 00 61 00 6c 00 73 00 20 00 28 00 4d 00 53 00 56 00 31 00 5f 00 30 00 2c 00 20 00 2e 00 2e 00 2e 00 29 00 } //1 LSASRV Credentials (MSV1_0, ...)
		$a_01_1 = {4b 00 45 00 52 00 42 00 45 00 52 00 4f 00 53 00 20 00 43 00 72 00 65 00 64 00 65 00 6e 00 74 00 69 00 61 00 6c 00 73 00 20 00 28 00 6e 00 6f 00 20 00 74 00 69 00 63 00 6b 00 65 00 74 00 73 00 2c 00 20 00 73 00 6f 00 72 00 72 00 79 00 29 00 } //1 KERBEROS Credentials (no tickets, sorry)
		$a_01_2 = {6d 00 69 00 6d 00 69 00 6c 00 6f 00 76 00 65 00 5f 00 6b 00 65 00 72 00 62 00 65 00 72 00 6f 00 73 00 } //1 mimilove_kerberos
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}