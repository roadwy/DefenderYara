
rule Trojan_Win32_Bitmin_NB_MTB{
	meta:
		description = "Trojan:Win32/Bitmin.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {e8 fb ef ff ff 8b 5c 24 90 01 01 2b c7 3b c3 73 02 8b d8 8b 56 90 01 01 83 c8 ff 2b c2 3b c3 77 05 90 00 } //5
		$a_01_1 = {56 43 36 5f 49 4e 5f 56 4d 5f 44 6c 6c 5f 32 } //1 VC6_IN_VM_Dll_2
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}