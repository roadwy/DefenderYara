
rule Trojan_Win32_Emotet_AL_MSR{
	meta:
		description = "Trojan:Win32/Emotet.AL!MSR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 00 6c 00 67 00 53 00 6d 00 70 00 6c 00 2e 00 44 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 } //01 00  DlgSmpl.Document
		$a_01_1 = {4d 00 50 00 41 00 44 00 56 00 46 00 4e 00 2e 00 44 00 4c 00 4c 00 } //01 00  MPADVFN.DLL
		$a_01_2 = {63 3a 5c 55 73 65 72 73 5c 55 73 65 72 5c 44 65 73 6b 74 6f 70 5c 32 30 30 35 5c 44 6c 67 53 6d 70 6c 5c 57 69 6e 52 65 6c 5c 44 6c 67 53 6d 70 6c 2e 70 64 62 } //01 00  c:\Users\User\Desktop\2005\DlgSmpl\WinRel\DlgSmpl.pdb
		$a_01_3 = {25 73 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 25 73 } //01 00  %s\shell\open\%s
		$a_01_4 = {44 6c 67 53 6d 70 6c } //00 00  DlgSmpl
	condition:
		any of ($a_*)
 
}