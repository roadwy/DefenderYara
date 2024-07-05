
rule Trojan_Win32_RedLineStealer_RP_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 46 69 72 73 74 2e 70 64 62 } //01 00  \First.pdb
		$a_01_1 = {53 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //01 00  SetThreadContext
		$a_01_2 = {52 65 73 75 6d 65 54 68 72 65 61 64 } //01 00  ResumeThread
		$a_01_3 = {5c 52 65 67 41 73 6d 2e 65 78 65 } //01 00  \RegAsm.exe
		$a_01_4 = {73 49 61 73 6e 6e 66 62 6e 78 68 62 73 41 55 69 65 } //00 00  sIasnnfbnxhbsAUie
	condition:
		any of ($a_*)
 
}