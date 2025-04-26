
rule Trojan_Win32_Detrahere_C{
	meta:
		description = "Trojan:Win32/Detrahere.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {5c 56 43 5f 50 72 6f 6a 65 63 74 5c 53 6d 61 72 74 53 65 72 76 69 63 65 5c 52 65 6c 65 61 73 65 5c 73 70 6c 73 72 76 2e 70 64 62 } //1 \VC_Project\SmartService\Release\splsrv.pdb
		$a_01_1 = {47 6c 6f 62 61 6c 5c 73 70 6c 73 72 76 } //1 Global\splsrv
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}