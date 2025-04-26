
rule Virus_Win32_Virlock_PAGC_MTB{
	meta:
		description = "Virus:Win32/Virlock.PAGC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 06 32 c2 90 88 07 42 46 90 47 49 e9 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}