
rule PWS_Win32_Wedsnot_A{
	meta:
		description = "PWS:Win32/Wedsnot.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {e8 6c 18 00 00 c7 05 a4 99 40 00 01 00 00 00 b8 64 00 00 00 3b 05 a4 99 40 00 7c 13 ff 35 a4 99 40 00 e8 79 1a 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}