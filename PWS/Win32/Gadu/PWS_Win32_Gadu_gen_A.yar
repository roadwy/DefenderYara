
rule PWS_Win32_Gadu_gen_A{
	meta:
		description = "PWS:Win32/Gadu.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {50 72 6f 64 75 63 74 20 20 20 3a 20 50 61 73 73 54 6f 6f 6c } //03 00 
		$a_01_1 = {43 6f 70 79 72 69 67 68 74 20 3a 20 62 79 20 6d 61 53 73 20 5b 63 34 66 5d } //01 00 
		$a_01_2 = {61 20 7a 20 47 61 64 75 } //00 00 
	condition:
		any of ($a_*)
 
}