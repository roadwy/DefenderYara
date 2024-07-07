
rule Ransom_Win32_WinLock_RDA_MTB{
	meta:
		description = "Ransom:Win32/WinLock.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {54 72 61 73 68 69 6e 67 20 74 68 65 20 73 79 73 74 65 6d 2e 2e 2e } //1 Trashing the system...
		$a_01_1 = {69 66 20 75 20 73 65 65 20 74 68 69 73 20 74 68 65 6e 20 75 72 20 73 79 73 74 65 6d 20 69 73 20 64 65 61 64 } //1 if u see this then ur system is dead
		$a_01_2 = {68 69 6c 64 61 62 6f 6f 2c 20 69 66 20 79 6f 75 20 73 65 65 20 74 68 69 73 } //1 hildaboo, if you see this
		$a_01_3 = {2c 20 69 6d 20 73 6f 72 72 79 2e } //1 , im sorry.
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}