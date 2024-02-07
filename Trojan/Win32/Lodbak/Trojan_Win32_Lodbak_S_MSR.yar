
rule Trojan_Win32_Lodbak_S_MSR{
	meta:
		description = "Trojan:Win32/Lodbak.S!MSR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 73 68 61 6e 65 31 5c 64 69 7a 7a 79 5c 6d 6f 6e 67 6f 6f 73 65 5c 72 75 69 69 67 65 71 72 2e 70 64 62 } //01 00  C:\shane1\dizzy\mongoose\ruiigeqr.pdb
		$a_01_1 = {72 75 69 69 67 65 71 72 2e 64 6c 6c } //00 00  ruiigeqr.dll
	condition:
		any of ($a_*)
 
}