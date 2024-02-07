
rule PWS_Win32_Delf_EJ{
	meta:
		description = "PWS:Win32/Delf.EJ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {69 6d 2d 63 68 65 61 74 65 72 2e 73 74 65 61 6c 40 } //01 00  im-cheater.steal@
		$a_02_1 = {73 6d 74 70 2e 79 61 6e 64 65 78 2e 72 75 90 02 0a 67 72 61 62 62 65 72 20 70 61 73 73 77 6f 72 64 90 02 0c 76 69 72 75 73 20 6c 6f 67 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}