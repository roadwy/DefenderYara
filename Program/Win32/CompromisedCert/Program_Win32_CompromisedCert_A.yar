
rule Program_Win32_CompromisedCert_A{
	meta:
		description = "Program:Win32/CompromisedCert.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {5c 53 75 70 65 72 66 69 73 68 5c 57 46 50 5c 44 72 69 76 65 72 5c 57 69 6e 38 52 65 6c 65 61 73 65 5c 78 90 01 02 5c 56 44 57 46 50 90 02 02 2e 70 64 62 90 00 } //01 00 
		$a_01_1 = {46 00 6c 00 6f 00 77 00 20 00 50 00 72 00 6f 00 78 00 79 00 20 00 72 00 65 00 64 00 69 00 72 00 65 00 63 00 74 00 6f 00 72 00 20 00 63 00 61 00 6c 00 6c 00 6f 00 75 00 74 00 } //01 00  Flow Proxy redirector callout
		$a_01_2 = {21 21 21 21 20 4b 72 6e 6c 48 6c 70 72 52 65 64 69 72 65 63 74 44 61 74 61 50 6f 70 75 6c 61 74 65 20 3a 20 } //01 00  !!!! KrnlHlprRedirectDataPopulate : 
		$a_01_3 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 56 00 44 00 57 00 46 00 50 00 } //00 00  \Device\VDWFP
	condition:
		any of ($a_*)
 
}