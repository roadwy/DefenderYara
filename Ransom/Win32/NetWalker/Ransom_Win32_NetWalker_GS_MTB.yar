
rule Ransom_Win32_NetWalker_GS_MTB{
	meta:
		description = "Ransom:Win32/NetWalker.GS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {4e 65 74 77 61 6c 6b 65 72 5f 64 6c 6c 2e 64 6c 6c 00 44 6f } //2
		$a_01_1 = {63 6f 64 65 5f 69 64 3a } //1 code_id:
		$a_01_2 = {6f 6e 69 6f 6e 31 } //1 onion1
		$a_01_3 = {6f 6e 69 6f 6e 32 } //1 onion2
		$a_01_4 = {6e 61 6d 65 73 7a } //1 namesz
		$a_01_5 = {75 6e 6c 6f 63 6b } //1 unlock
		$a_01_6 = {70 73 70 61 74 68 } //1 pspath
	condition:
		((#a_00_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}