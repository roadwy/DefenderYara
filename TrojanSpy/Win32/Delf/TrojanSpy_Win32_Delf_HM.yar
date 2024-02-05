
rule TrojanSpy_Win32_Delf_HM{
	meta:
		description = "TrojanSpy:Win32/Delf.HM,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 69 70 6f 3d 00 00 00 ff ff ff ff 07 00 00 00 6e 6f 6d 65 70 63 3d 00 ff ff ff ff 04 00 00 00 69 6e 66 3d 00 } //01 00 
		$a_01_1 = {2e 74 78 74 00 00 00 00 6e 65 74 20 73 74 6f 70 20 53 68 61 72 65 64 41 63 63 65 73 73 00 } //00 00 
	condition:
		any of ($a_*)
 
}