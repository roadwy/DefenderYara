
rule PWS_Win32_Populf_B{
	meta:
		description = "PWS:Win32/Populf.B,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b8 01 00 00 00 e8 98 ee ff ff 8b 55 e8 b8 a8 cc 40 00 b9 38 a1 40 00 e8 de a0 ff ff 8d 55 e4 b8 01 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}