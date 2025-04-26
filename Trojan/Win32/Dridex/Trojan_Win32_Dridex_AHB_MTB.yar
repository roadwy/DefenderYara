
rule Trojan_Win32_Dridex_AHB_MTB{
	meta:
		description = "Trojan:Win32/Dridex.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {57 45 51 53 44 45 7c 54 2e 70 64 62 } //WEQSDE|T.pdb  3
		$a_80_1 = {6b 65 72 6e 65 6c 33 32 2e 53 6c 65 65 70 } //kernel32.Sleep  3
		$a_80_2 = {44 34 31 69 6e 74 65 72 72 75 70 74 4c 65 61 6b 65 64 36 4a 66 } //D41interruptLeaked6Jf  3
		$a_80_3 = {43 68 72 6f 6d 65 6e 73 75 62 6d 65 6e 75 37 36 53 74 6f 72 65 31 36 34 65 6d 61 6e 61 67 65 } //Chromensubmenu76Store164emanage  3
		$a_80_4 = {62 61 63 6b 6f 76 64 65 66 61 75 6c 74 32 } //backovdefault2  3
		$a_80_5 = {71 63 6d 4c 61 6c 6c 58 48 65 78 63 65 70 74 73 61 6c 6c 6f 77 73 } //qcmLallXHexceptsallows  3
		$a_80_6 = {56 65 31 74 65 65 6e 73 4d 65 73 73 65 6e 67 65 72 31 37 32 74 68 65 78 } //Ve1teensMessenger172thex  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}