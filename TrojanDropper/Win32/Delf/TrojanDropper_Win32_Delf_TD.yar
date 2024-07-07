
rule TrojanDropper_Win32_Delf_TD{
	meta:
		description = "TrojanDropper:Win32/Delf.TD,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0e 50 72 6f 63 75 72 61 44 72 69 76 65 72 73 90 01 06 04 44 69 63 6f 90 01 06 0a 43 72 69 41 72 71 75 69 76 6f 90 01 06 0c 41 62 72 65 50 72 6f 63 65 73 73 6f 90 01 06 0a 46 6f 72 6d 43 72 65 61 74 65 90 01 06 05 53 74 61 72 74 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}