
rule DoS_Win32_ZeroBlade_A_dha{
	meta:
		description = "DoS:Win32/ZeroBlade.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,ffffffc8 00 ffffffc8 00 02 00 00 "
		
	strings :
		$a_43_0 = {69 00 00 00 66 89 90 01 03 ba 73 00 00 00 66 89 90 01 03 b9 61 00 00 00 90 00 64 } //100
		$a_8b_1 = {24 2c c1 e7 0a 57 6a 40 ff 00 00 5d 04 00 00 28 6f 05 80 5c 27 00 00 2b 6f 05 80 00 00 01 00 08 00 11 00 af 01 53 63 61 72 73 69 2e 4d 42 42 4d 21 4d 54 42 00 00 01 40 05 82 70 00 04 00 78 80 00 } //2816
	condition:
		((#a_43_0  & 1)*100+(#a_8b_1  & 1)*2816) >=200
 
}