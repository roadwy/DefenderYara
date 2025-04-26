
rule Backdoor_Win32_Lotok_GNL_MTB{
	meta:
		description = "Backdoor:Win32/Lotok.GNL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {b1 61 b2 72 88 4c 24 ?? 88 4c 24 ?? 8d 4c 24 ?? b0 65 51 68 ?? ?? ?? ?? c6 44 24 ?? 43 88 54 24 ?? 88 44 24 ?? c6 44 24 ?? 74 88 44 24 ?? c6 44 24 ?? 54 c6 44 24 ?? 68 88 54 24 ?? 88 44 24 ?? c6 44 24 ?? 64 c6 44 ?? 24 00 ff 15 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}