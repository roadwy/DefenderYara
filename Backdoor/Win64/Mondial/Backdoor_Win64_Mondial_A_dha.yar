
rule Backdoor_Win64_Mondial_A_dha{
	meta:
		description = "Backdoor:Win64/Mondial.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {41 0f b6 08 b8 ?? ?? ?? ?? 49 ff c0 80 f1 ?? f7 e7 c1 ea 05 b0 64 f6 ea 02 c1 40 2a c7 ff c7 41 88 40 ff } //1
		$a_03_1 = {48 8d 4c 24 ?? c6 44 24 ?? 41 c6 44 24 ?? 64 c6 44 24 ?? 76 c6 44 24 ?? 61 c6 44 24 ?? 70 c6 44 24 ?? 69 c6 44 24 ?? 33 c6 44 24 ?? 32 c6 44 24 ?? 2e c6 44 24 ?? 64 c6 44 24 ?? 6c c6 44 24 ?? 6c } //1
		$a_00_2 = {c6 44 24 60 52 c6 44 24 61 65 c6 44 24 62 67 c6 44 24 63 69 c6 44 24 64 73 c6 44 24 65 74 c6 44 24 66 65 c6 44 24 67 72 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1) >=2
 
}