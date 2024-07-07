
rule Backdoor_Win32_Lotok_GNL_MTB{
	meta:
		description = "Backdoor:Win32/Lotok.GNL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {b1 61 b2 72 88 4c 24 90 01 01 88 4c 24 90 01 01 8d 4c 24 90 01 01 b0 65 51 68 90 01 04 c6 44 24 90 01 01 43 88 54 24 90 01 01 88 44 24 90 01 01 c6 44 24 90 01 01 74 88 44 24 90 01 01 c6 44 24 90 01 01 54 c6 44 24 90 01 01 68 88 54 24 90 01 01 88 44 24 90 01 01 c6 44 24 90 01 01 64 c6 44 90 01 01 24 00 ff 15 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}