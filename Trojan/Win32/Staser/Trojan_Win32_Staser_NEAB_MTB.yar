
rule Trojan_Win32_Staser_NEAB_MTB{
	meta:
		description = "Trojan:Win32/Staser.NEAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 07 00 00 "
		
	strings :
		$a_01_0 = {6b 4f 77 41 23 4f 77 44 64 4f 77 } //5 kOwA#OwDdOw
		$a_01_1 = {54 4f 77 71 6c 4f 77 } //5 TOwqlOw
		$a_01_2 = {2e 64 6d 63 31 30 32 } //5 .dmc102
		$a_01_3 = {50 00 68 00 6f 00 74 00 6f 00 52 00 65 00 6e 00 61 00 6d 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //5 PhotoRenamer.exe
		$a_01_4 = {34 00 2e 00 31 00 2e 00 33 00 2e 00 31 00 30 00 32 00 } //5 4.1.3.102
		$a_01_5 = {54 00 47 00 4d 00 44 00 65 00 76 00 } //5 TGMDev
		$a_01_6 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5+(#a_01_5  & 1)*5+(#a_01_6  & 1)*1) >=31
 
}