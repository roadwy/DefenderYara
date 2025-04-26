
rule PWS_Win32_Populf_B_dll{
	meta:
		description = "PWS:Win32/Populf.B!dll,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {68 12 01 00 00 50 e8 63 0c fd ff 6a 00 68 5c 62 43 00 e8 b7 0b fd ff 85 c0 74 0d 6a 00 68 b4 5f 43 00 50 e8 86 0b fd ff 5d c2 14 00 00 00 41 56 50 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}