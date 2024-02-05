
rule PWS_Win32_Fareit_ZT_MTB{
	meta:
		description = "PWS:Win32/Fareit.ZT!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 43 8b 32 42 42 42 42 8a 06 88 07 46 47 49 75 f7 0f b7 0b 81 f9 7a 17 00 00 72 e4 } //00 00 
	condition:
		any of ($a_*)
 
}