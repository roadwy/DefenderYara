
rule Trojan_Win32_SysWiper_GX_MTB{
	meta:
		description = "Trojan:Win32/SysWiper.GX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 04 00 00 "
		
	strings :
		$a_01_0 = {46 69 6c 65 45 6e 63 2e 70 64 62 } //10 FileEnc.pdb
		$a_00_1 = {5c 00 47 00 4c 00 4f 00 42 00 41 00 4c 00 52 00 4f 00 4f 00 54 00 } //10 \GLOBALROOT
		$a_01_2 = {43 3a 5c 70 61 74 68 5c 74 6f 5c 66 69 6c 65 2e 74 78 74 } //10 C:\path\to\file.txt
		$a_01_3 = {46 69 6c 65 20 6f 76 65 72 77 72 69 74 74 65 6e 20 61 6e 64 20 64 65 6c 65 74 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 } //10 File overwritten and deleted successfully
	condition:
		((#a_01_0  & 1)*10+(#a_00_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10) >=40
 
}