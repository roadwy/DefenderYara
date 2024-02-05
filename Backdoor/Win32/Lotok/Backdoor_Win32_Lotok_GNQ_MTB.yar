
rule Backdoor_Win32_Lotok_GNQ_MTB{
	meta:
		description = "Backdoor:Win32/Lotok.GNQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {32 c3 2a c3 32 c3 89 2d 90 01 04 8b 2d 90 01 04 02 c3 88 04 17 03 e9 83 c4 90 01 01 47 89 0d 90 01 04 89 2d 90 01 04 84 c0 90 01 02 8b 44 24 90 01 01 83 c6 90 01 01 03 c6 3b 44 24 90 01 01 0f 8c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}