
rule PWS_Win32_Sipay_A{
	meta:
		description = "PWS:Win32/Sipay.A,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 00 69 00 6e 00 61 00 6c 00 20 00 52 00 53 00 20 00 53 00 74 00 65 00 61 00 6c 00 65 00 72 00 5c 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 31 00 2e 00 76 00 62 00 70 00 } //01 00  Final RS Stealer\Project1.vbp
		$a_01_1 = {52 53 20 53 74 65 61 6c 65 72 20 76 } //03 00  RS Stealer v
		$a_01_2 = {52 53 5f 53 74 65 61 6c 65 72 } //03 00  RS_Stealer
		$a_01_3 = {50 61 73 73 77 6f 72 64 20 20 3a } //03 00  Password  :
		$a_01_4 = {46 54 50 20 53 65 72 76 65 72 20 3a } //00 00  FTP Server :
	condition:
		any of ($a_*)
 
}