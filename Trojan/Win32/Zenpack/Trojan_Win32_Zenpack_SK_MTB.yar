
rule Trojan_Win32_Zenpack_SK_MTB{
	meta:
		description = "Trojan:Win32/Zenpack.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {74 68 69 72 64 66 65 6d 61 6c 65 66 69 73 68 67 72 65 65 6e 2e } //1 thirdfemalefishgreen.
		$a_81_1 = {4f 53 70 6c 61 63 65 2e 73 63 61 74 74 6c 65 73 6c 59 69 65 6c 64 69 6e 67 50 73 61 77 2e } //1 OSplace.scattleslYieldingPsaw.
		$a_81_2 = {44 6f 6e 2e 74 77 65 6d 61 6b 65 65 76 65 6e 69 6e 67 67 6d 61 64 65 61 6c 6c 2e 63 72 65 61 74 65 64 2e 4a } //1 Don.twemakeeveninggmadeall.created.J
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}