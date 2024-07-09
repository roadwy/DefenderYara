
rule PWS_Win32_QQthief_L_bit{
	meta:
		description = "PWS:Win32/QQthief.L!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {25 73 5c 7e 40 55 77 ?? ?? 2e 61 76 69 00 00 00 56 69 64 65 6f 4d 6f 75 73 65 50 69 63 } //2
		$a_03_1 = {25 73 2e 64 6c 6c [0-04] 55 73 65 72 33 32 } //1
		$a_03_2 = {25 73 33 32 2e 64 6c 6c [0-04] 55 73 65 72 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}