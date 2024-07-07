
rule PWS_Win32_QQthief_L_bit{
	meta:
		description = "PWS:Win32/QQthief.L!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {25 73 5c 7e 40 55 77 90 01 02 2e 61 76 69 00 00 00 56 69 64 65 6f 4d 6f 75 73 65 50 69 63 90 00 } //2
		$a_03_1 = {25 73 2e 64 6c 6c 90 02 04 55 73 65 72 33 32 90 00 } //1
		$a_03_2 = {25 73 33 32 2e 64 6c 6c 90 02 04 55 73 65 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}