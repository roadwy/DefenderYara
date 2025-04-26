
rule PWS_Win32_Frethog_AF{
	meta:
		description = "PWS:Win32/Frethog.AF,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b d1 c1 e9 02 f3 a5 8b ca 83 e1 03 f3 a4 c6 04 10 e9 8b cb 2b c8 83 e9 05 89 4c 10 01 c6 03 e9 8b 45 0c 2b c3 83 e8 05 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}