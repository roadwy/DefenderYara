
rule PWS_Win32_Fareit_MW_MTB{
	meta:
		description = "PWS:Win32/Fareit.MW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {29 cb 83 c3 90 01 01 8d 0b c1 c1 90 01 01 d1 c9 6a 90 01 01 8f 02 01 1a 8d 52 90 01 01 83 ef 90 01 04 8d 1d 90 01 04 8d 9b 90 09 09 00 83 ee 90 01 01 83 c3 90 01 01 c1 cb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}