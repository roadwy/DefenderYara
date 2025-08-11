
rule Trojan_Win32_Guloader_LXC_MTB{
	meta:
		description = "Trojan:Win32/Guloader.LXC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {4e 61 73 65 62 65 72 72 79 2e 66 69 6e } //1 Naseberry.fin
		$a_81_1 = {62 72 75 73 68 6e 65 2e 62 72 6f } //1 brushne.bro
		$a_81_2 = {70 69 63 63 6f 6c 6f 65 72 6e 65 73 2e 65 6e 65 } //1 piccoloernes.ene
		$a_81_3 = {70 6f 6c 79 62 72 69 64 2e 69 6e 64 } //1 polybrid.ind
		$a_81_4 = {5c 63 68 61 75 73 73 65 62 72 6f 6c 67 6e 69 6e 67 65 72 6e 65 73 5c 70 72 6f 76 65 6e 63 65 } //1 \chaussebrolgningernes\provence
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}