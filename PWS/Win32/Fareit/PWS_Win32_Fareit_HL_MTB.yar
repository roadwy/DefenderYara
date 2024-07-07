
rule PWS_Win32_Fareit_HL_MTB{
	meta:
		description = "PWS:Win32/Fareit.HL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {01 f3 51 b9 00 00 00 00 01 d9 31 01 59 5b 51 b9 90 01 04 01 f1 68 90 01 04 89 04 24 b8 90 01 04 01 c8 01 18 58 59 55 89 04 24 b8 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}