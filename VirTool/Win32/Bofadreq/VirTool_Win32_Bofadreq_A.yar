
rule VirTool_Win32_Bofadreq_A{
	meta:
		description = "VirTool:Win32/Bofadreq.A,SIGNATURE_TYPE_PEHSTR,07 00 07 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 65 72 74 2e 74 65 73 74 72 61 6e 67 65 2e 6c 6f 63 61 6c } //01 00  Cert.testrange.local
		$a_01_1 = {43 65 72 74 52 65 71 75 65 73 74 32 2d 3e 6c 70 56 74 62 6c 2d 3e 47 65 74 52 65 71 75 65 73 74 49 64 28 29 } //05 00  CertRequest2->lpVtbl->GetRequestId()
		$a_01_2 = {61 64 63 73 5f 72 65 71 75 65 73 74 20 53 55 43 43 45 53 53 } //00 00  adcs_request SUCCESS
	condition:
		any of ($a_*)
 
}