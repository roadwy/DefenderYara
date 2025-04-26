
rule Backdoor_Win32_Lotok_GZX_MTB{
	meta:
		description = "Backdoor:Win32/Lotok.GZX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {53 50 c7 44 24 ?? 45 50 45 72 c7 44 24 ?? 6f 45 63 65 c7 44 24 ?? 45 73 45 73 c7 44 24 ?? 45 33 45 32 c7 44 24 ?? 46 45 69 45 c7 44 24 ?? 72 45 73 45 c7 44 24 ?? 74 45 45 45 89 5c 24 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}