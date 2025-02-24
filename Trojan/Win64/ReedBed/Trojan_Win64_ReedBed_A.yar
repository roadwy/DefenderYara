
rule Trojan_Win64_ReedBed_A{
	meta:
		description = "Trojan:Win64/ReedBed.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {48 6f 6f 6b 4e 74 43 72 65 61 74 65 55 73 65 72 50 72 6f 63 65 73 73 28 29 3a 20 6f 6b 21 } //1 HookNtCreateUserProcess(): ok!
		$a_01_1 = {48 6f 6f 6b 52 74 6c 45 78 69 74 55 73 65 72 50 72 6f 63 65 73 73 28 29 3a 20 52 74 6c 45 78 69 74 55 73 65 72 50 72 6f 63 65 73 73 20 6e 6f 74 20 66 6f 75 6e 64 20 68 4e 74 64 6c 6c 3d 25 23 70 } //1 HookRtlExitUserProcess(): RtlExitUserProcess not found hNtdll=%#p
		$a_01_2 = {5c 62 63 5f 73 73 6c 5f 63 6c 69 65 6e 74 2e } //1 \bc_ssl_client.
		$a_01_3 = {73 65 6e 64 5f 70 69 70 65 5f 73 73 6c 28 29 3a 20 53 53 4c 5f 77 72 69 74 65 28 29 3a 20 53 53 4c 5f 45 52 52 4f 52 5f 57 41 4e 54 5f 57 52 49 54 45 } //1 send_pipe_ssl(): SSL_write(): SSL_ERROR_WANT_WRITE
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}