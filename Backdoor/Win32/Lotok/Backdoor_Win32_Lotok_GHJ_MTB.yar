
rule Backdoor_Win32_Lotok_GHJ_MTB{
	meta:
		description = "Backdoor:Win32/Lotok.GHJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {b0 65 88 44 24 90 01 01 88 44 24 90 01 01 88 44 24 90 01 01 8d 44 24 90 01 01 50 51 c6 44 24 90 01 01 43 c6 44 24 90 01 01 72 c6 44 24 90 01 01 61 c6 44 24 90 01 01 74 c6 44 24 90 01 01 45 c6 44 24 90 01 01 76 c6 44 24 90 01 01 6e c6 44 24 90 01 01 74 c6 44 24 90 01 01 41 88 5c 24 90 01 01 ff d7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}