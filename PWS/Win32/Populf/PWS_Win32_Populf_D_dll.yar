
rule PWS_Win32_Populf_D_dll{
	meta:
		description = "PWS:Win32/Populf.D!dll,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {fd ff b9 01 00 00 00 33 d2 b8 02 00 00 00 e8 c3 fe ff ff 33 c9 33 d2 b8 04 00 00 00 e8 b5 fe ff ff e8 70 fe ff ff eb 0a 68 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}