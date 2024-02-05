
rule Trojan_Win32_FormBook_N_MTB{
	meta:
		description = "Trojan:Win32/FormBook.N!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_02_0 = {8b 19 81 ff 90 01 04 81 fa 90 00 } //02 00 
		$a_02_1 = {31 1c 10 81 ff 90 01 04 81 fb 90 01 04 83 c2 04 90 00 } //01 00 
		$a_00_2 = {89 04 1f 71 } //03 00 
		$a_00_3 = {35 a8 d6 00 6a eb } //00 00 
	condition:
		any of ($a_*)
 
}