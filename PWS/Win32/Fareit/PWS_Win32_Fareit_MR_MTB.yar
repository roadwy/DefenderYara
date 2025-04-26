
rule PWS_Win32_Fareit_MR_MTB{
	meta:
		description = "PWS:Win32/Fareit.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 1a 80 f3 ?? 88 5d [0-06] 8b 5d ?? 8b fb 8a 5d ?? 88 1f [0-04] 83 c6 ?? 73 ?? e8 [0-0c] 42 49 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}