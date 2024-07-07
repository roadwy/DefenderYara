
rule Trojan_MacOS_SAgnt_C_MTB{
	meta:
		description = "Trojan:MacOS/SAgnt.C!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {6d 61 69 6e 2e 63 72 65 61 74 65 50 6c 69 73 74 } //1 main.createPlist
		$a_00_1 = {4d 50 41 67 65 6e 74 2e 67 6f } //1 MPAgent.go
		$a_00_2 = {73 74 6f 70 61 64 } //1 stopad
		$a_00_3 = {6c 69 62 63 5f 65 78 65 63 76 65 5f 74 72 61 6d 70 6f 6c 69 6e 65 } //1 libc_execve_trampoline
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}