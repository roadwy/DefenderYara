
rule PWS_Win32_Delf_BP{
	meta:
		description = "PWS:Win32/Delf.BP,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {50 4b 31 31 5f 47 65 74 49 6e 74 65 72 6e 61 6c 4b 65 79 53 6c 6f 74 20 46 61 69 6c 65 64 21 } //1 PK11_GetInternalKeySlot Failed!
		$a_03_1 = {2d 2d 2d 44 65 73 76 61 6c 69 6a 61 64 6f 72 20 76 31 2e [30-39] 20 62 79 20 74 61 6b 65 64 6f 77 6e 2d 2d } //4
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*4) >=5
 
}