
rule Trojan_Win32_IcedId_SC_MTB{
	meta:
		description = "Trojan:Win32/IcedId.SC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 04 00 00 0a 00 "
		
	strings :
		$a_02_0 = {00 cc 49 3e 22 e8 34 5b e9 90 02 05 03 e2 ff 90 02 06 3e cc ff cc e9 90 00 } //0a 00 
		$a_00_1 = {63 3a 5c 4f 72 64 65 72 5c 73 68 61 72 70 5c 54 72 65 65 5c 73 74 61 6e 64 46 69 6c 6c 2e 70 64 62 } //01 00  c:\Order\sharp\Tree\standFill.pdb
		$a_00_2 = {69 00 63 00 65 00 73 00 75 00 69 00 74 00 2e 00 65 00 78 00 65 00 } //0a 00  icesuit.exe
		$a_00_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //00 00  IsDebuggerPresent
		$a_00_4 = {5d 04 00 00 98 7e 04 80 5c 2a 00 00 99 7e 04 80 00 00 01 00 08 00 14 00 ac 21 44 65 6c 66 } //49 6e 
	condition:
		any of ($a_*)
 
}