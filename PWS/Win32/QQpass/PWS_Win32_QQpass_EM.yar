
rule PWS_Win32_QQpass_EM{
	meta:
		description = "PWS:Win32/QQpass.EM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {52 53 45 54 0d 0a 00 00 4d 41 49 4c 20 46 52 4f 4d 3a 3c 25 73 3e 0d 0a } //1
		$a_01_1 = {0d 0a 20 51 51 c3 dc c2 eb a3 ba 00 20 51 51 ba c5 c2 eb a3 ba 00 68 61 63 6b 64 6f 6e 67 40 31 36 33 2e 63 6f 6d } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}