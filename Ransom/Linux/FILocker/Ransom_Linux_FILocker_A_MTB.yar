
rule Ransom_Linux_FILocker_A_MTB{
	meta:
		description = "Ransom:Linux/FILocker.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 6d 61 6b 65 52 65 61 64 6d 65 2e 66 75 6e 63 } //2 main.makeReadme.func
		$a_01_1 = {6d 61 69 6e 2e 64 65 6c 65 74 65 53 65 6c 66 } //2 main.deleteSelf
		$a_01_2 = {6d 61 69 6e 2e 77 61 6c 6b 2d 74 72 61 6d 70 30 } //1 main.walk-tramp0
		$a_01_3 = {6d 61 69 6e 2e 54 61 62 6c 65 54 6f 67 67 6c 65 4f 62 66 } //1 main.TableToggleObf
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}