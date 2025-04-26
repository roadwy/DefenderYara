
rule Backdoor_Win32_Lotok_GZZ_MTB{
	meta:
		description = "Backdoor:Win32/Lotok.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {dc 52 65 41 6c 50 c7 45 ?? 6c 6f 63 00 c7 45 ?? 4b 45 52 4e c7 45 ?? 45 4c 33 32 c7 45 ?? 2e 64 6c 6c c6 45 ?? 00 c7 45 ?? 4c 6f 61 64 c7 45 ?? 4c 69 62 72 c7 45 ?? 61 72 79 41 c6 45 ?? 00 ff d3 50 ff d6 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}