
rule Trojan_Win32_Farfli_MD_MTB{
	meta:
		description = "Trojan:Win32/Farfli.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 06 00 00 "
		
	strings :
		$a_01_0 = {50 4b 56 67 73 4e 74 77 4e 61 6c 42 4e 7a 71 6c 56 6f 69 74 56 4b 45 6b 6a 54 49 42 70 70 6b 7a } //5 PKVgsNtwNalBNzqlVoitVKEkjTIBppkz
		$a_01_1 = {76 6c 79 4f 57 4f 4b 75 68 52 43 50 5a 48 65 71 69 61 7a 62 4a 47 68 41 78 4e 4b 61 79 64 76 65 } //5 vlyOWOKuhRCPZHeqiazbJGhAxNKaydve
		$a_01_2 = {2e 73 79 6d 74 61 62 } //1 .symtab
		$a_01_3 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //1 WaitForSingleObject
		$a_01_4 = {53 77 69 74 63 68 54 6f 54 68 72 65 61 64 } //1 SwitchToThread
		$a_01_5 = {53 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //1 SetThreadContext
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=14
 
}
rule Trojan_Win32_Farfli_MD_MTB_2{
	meta:
		description = "Trojan:Win32/Farfli.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {c6 45 dd 59 c6 45 de 53 c6 45 df 54 c6 45 e0 45 c6 45 e1 4d c6 45 e2 5c c6 45 e3 43 c6 45 e4 75 c6 45 e5 72 c6 45 e6 72 c6 45 e7 65 c6 45 e8 6e c6 45 e9 74 c6 45 ea 43 c6 45 eb 6f c6 45 ec 6e c6 45 ed 74 c6 45 ee 72 c6 45 ef 6f c6 45 f0 6c c6 45 f1 53 c6 45 f2 65 c6 45 f3 74 c6 45 f4 5c c6 45 f5 53 c6 45 f6 65 c6 45 f7 72 c6 45 f8 76 c6 45 f9 69 c6 45 fa 63 c6 45 fb 65 c6 45 fc 73 c6 45 fd 5c 88 ?? fe } //10
		$a_81_1 = {53 65 72 70 69 65 69 } //1 Serpiei
	condition:
		((#a_03_0  & 1)*10+(#a_81_1  & 1)*1) >=11
 
}