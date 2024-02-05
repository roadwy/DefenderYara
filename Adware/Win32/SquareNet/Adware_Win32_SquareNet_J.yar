
rule Adware_Win32_SquareNet_J{
	meta:
		description = "Adware:Win32/SquareNet.J,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 63 20 73 74 61 72 74 20 22 22 20 22 25 73 22 20 25 73 } //01 00 
		$a_01_1 = {46 3a 5c 64 6f 77 6e 6c 6f 61 64 65 72 5c 64 6f 77 6e 6c 6f 61 64 5f 6d 67 72 5c 52 65 6c 65 61 73 65 5c 73 68 65 6c 6c 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}