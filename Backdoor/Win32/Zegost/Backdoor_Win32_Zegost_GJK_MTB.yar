
rule Backdoor_Win32_Zegost_GJK_MTB{
	meta:
		description = "Backdoor:Win32/Zegost.GJK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {b0 45 b1 52 68 ?? ?? ?? ?? c6 44 24 ?? 47 88 44 24 ?? c6 44 24 ?? 54 c6 44 24 ?? 53 88 44 24 ?? 88 4c 24 ?? c6 44 24 ?? 56 88 44 24 ?? 88 4c 24 ?? c6 44 24 ?? 32 c6 44 24 ?? 2e c6 44 24 ?? 30 88 5c 24 ?? e8 ?? ?? ?? ?? 83 c4 04 89 44 24 64 3b c3 c6 84 24 } //10
		$a_01_1 = {70 72 6f 67 72 61 6d 42 2e 65 78 65 } //1 programB.exe
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}