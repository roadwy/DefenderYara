
rule Trojan_Win64_Lotok_RW_MTB{
	meta:
		description = "Trojan:Win64/Lotok.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 48 89 e5 48 83 ec 08 44 8b cb 41 81 f0 6e 74 65 6c 41 81 f0 6e 74 65 6c 48 83 c0 08 } //01 00 
		$a_01_1 = {48 00 6f 00 6f 00 6b 00 57 00 6e 00 64 00 36 00 34 00 2e 00 45 00 58 00 45 00 } //00 00  HookWnd64.EXE
	condition:
		any of ($a_*)
 
}