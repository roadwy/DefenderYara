
rule TrojanSpy_Win32_Delf_HO{
	meta:
		description = "TrojanSpy:Win32/Delf.HO,SIGNATURE_TYPE_PEHSTR,09 00 09 00 0b 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 72 6f 6d 3a 20 00 00 ff ff ff ff 04 00 00 00 63 63 3a 20 } //02 00 
		$a_01_1 = {6e 65 74 20 73 74 6f 70 20 53 68 61 72 65 64 41 63 63 65 73 73 } //02 00  net stop SharedAccess
		$a_01_2 = {6e 65 74 73 68 20 66 69 72 65 77 61 6c 6c 20 6f 70 6d 6f 64 65 20 64 69 73 61 62 6c 65 } //02 00  netsh firewall opmode disable
		$a_01_3 = {4d 41 49 4c 00 00 00 00 45 58 45 46 49 4c 45 00 } //01 00 
		$a_01_4 = {2e 74 78 74 } //01 00  .txt
		$a_01_5 = {2a 2e 6d 62 6f 78 } //01 00  *.mbox
		$a_01_6 = {2a 2e 77 61 62 } //01 00  *.wab
		$a_01_7 = {2a 2e 6d 62 78 } //01 00  *.mbx
		$a_01_8 = {2a 2e 65 6d 6c } //01 00  *.eml
		$a_01_9 = {2a 2e 74 62 62 } //01 00  *.tbb
		$a_01_10 = {4f 50 45 4e 20 00 00 00 ff ff ff ff 0d 00 00 00 55 53 45 52 20 25 73 40 25 73 40 25 73 00 } //00 00 
	condition:
		any of ($a_*)
 
}