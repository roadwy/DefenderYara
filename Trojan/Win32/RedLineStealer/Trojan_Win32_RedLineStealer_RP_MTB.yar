
rule Trojan_Win32_RedLineStealer_RP_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 46 69 72 73 74 2e 70 64 62 } //1 \First.pdb
		$a_01_1 = {53 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //1 SetThreadContext
		$a_01_2 = {52 65 73 75 6d 65 54 68 72 65 61 64 } //1 ResumeThread
		$a_01_3 = {5c 52 65 67 41 73 6d 2e 65 78 65 } //1 \RegAsm.exe
		$a_01_4 = {73 49 61 73 6e 6e 66 62 6e 78 68 62 73 41 55 69 65 } //1 sIasnnfbnxhbsAUie
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}