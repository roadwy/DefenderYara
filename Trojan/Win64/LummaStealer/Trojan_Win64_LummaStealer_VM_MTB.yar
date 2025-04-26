
rule Trojan_Win64_LummaStealer_VM_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.VM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 52 44 46 } //1 main.RDF
		$a_01_1 = {6d 61 69 6e 2e 56 5a 43 4f 51 7a 65 68 43 70 } //2 main.VZCOQzehCp
		$a_01_2 = {6d 61 69 6e 2e 57 6a 4c 52 4d 75 4e 61 6f 72 } //1 main.WjLRMuNaor
		$a_01_3 = {6d 61 69 6e 2e 45 46 54 63 6d 55 67 45 74 54 } //2 main.EFTcmUgEtT
		$a_01_4 = {6d 61 69 6e 2e 66 61 71 4c 53 52 57 52 6c 56 } //1 main.faqLSRWRlV
		$a_01_5 = {6d 61 69 6e 2e 6c 6e 65 6a 59 77 66 5a 6b 6d } //2 main.lnejYwfZkm
		$a_01_6 = {6d 61 69 6e 2e 69 69 51 68 4e 42 6e 6e 66 6f } //1 main.iiQhNBnnfo
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*2+(#a_01_6  & 1)*1) >=5
 
}