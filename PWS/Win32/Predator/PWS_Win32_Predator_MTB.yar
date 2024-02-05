
rule PWS_Win32_Predator_MTB{
	meta:
		description = "PWS:Win32/Predator!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a ca 80 f1 04 88 0c 02 42 81 fa 90 01 04 72 ef 90 00 } //01 00 
		$a_02_1 = {0f b6 84 34 90 01 04 0f b6 c9 03 c8 0f b6 c1 0f b6 84 04 90 01 04 30 44 3c 18 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}