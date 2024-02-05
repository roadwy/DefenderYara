
rule Backdoor_Win32_Lotok_GNO_MTB{
	meta:
		description = "Backdoor:Win32/Lotok.GNO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {b0 65 b2 72 88 44 24 90 01 01 88 44 24 90 01 01 88 44 24 90 01 01 8d 44 24 90 01 01 b1 61 50 68 90 01 04 c6 44 24 90 01 01 43 88 54 24 90 01 01 88 4c 24 90 01 01 c6 44 24 90 01 01 74 c6 44 24 90 01 01 54 c6 44 24 90 01 01 68 88 54 24 20 88 4c 24 90 01 01 c6 44 24 90 01 01 64 c6 44 90 01 01 24 00 ff d5 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}