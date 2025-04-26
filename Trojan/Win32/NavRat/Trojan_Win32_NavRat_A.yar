
rule Trojan_Win32_NavRat_A{
	meta:
		description = "Trojan:Win32/NavRat.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 72 65 63 6f 6d 50 72 6f 63 20 3a 20 53 65 63 6f 6e 64 20 44 6f 77 6e 6c 6f 61 64 20 61 6e 64 20 53 68 65 6c 6c 45 78 65 63 75 74 65 20 4f 6b } //1 PrecomProc : Second Download and ShellExecute Ok
		$a_01_1 = {55 70 6c 6f 61 64 50 72 6f 63 20 3a 20 25 73 20 45 6e 63 44 65 63 46 69 6c 65 20 66 61 69 6c 65 64 } //1 UploadProc : %s EncDecFile failed
		$a_01_2 = {50 72 65 70 72 6f 63 20 3a 20 6d 61 70 70 69 6e 67 20 73 65 6c 66 20 65 78 65 20 74 6f 20 69 65 78 70 6c 6f 72 65 20 70 72 6f 63 65 73 73 } //1 Preproc : mapping self exe to iexplore process
		$a_01_3 = {50 72 65 63 6f 6d 45 78 65 20 3a 20 72 65 74 75 72 6e 65 64 20 66 72 6f 6d 20 50 72 65 70 72 6f 63 } //1 PrecomExe : returned from Preproc
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}