
rule PWS_Win32_QQpass_CIK{
	meta:
		description = "PWS:Win32/QQpass.CIK,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {bb b6 d3 ad ca b9 d3 c3 33 51 b4 f3 b5 c1 a3 a1 0d 0a d7 f7 d5 df d0 a1 c8 fd 20 51 51 a3 ba 35 33 39 39 39 34 38 0d 0a } //1
		$a_01_1 = {ce a8 d2 bb b9 d9 b7 bd b2 a9 bf cd a3 ba 68 74 74 70 3a 2f 2f 68 69 2e 62 61 69 64 75 2e 63 6f 6d 2f 71 71 35 33 39 39 39 34 38 0d 0a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}