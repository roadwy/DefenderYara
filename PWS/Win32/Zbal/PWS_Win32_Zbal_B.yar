
rule PWS_Win32_Zbal_B{
	meta:
		description = "PWS:Win32/Zbal.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {74 13 32 06 46 bb ff 00 00 00 21 c3 c1 e8 08 33 04 9f 49 75 e5 } //1
		$a_01_1 = {ac 32 d0 51 6a 08 59 d1 ea 73 03 33 55 fc e2 f7 59 e2 ed } //1
		$a_01_2 = {73 74 61 72 61 79 61 6d 6f 73 6b 76 61 } //1 starayamoskva
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}