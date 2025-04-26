
rule Trojan_Win32_LummaStealer_GC_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 43 6f 63 4c 59 46 4f 4f 6f 61 } //2 main.CocLYFOOoa
		$a_01_1 = {6d 61 69 6e 2e 6c 46 44 66 69 67 50 4f 46 71 } //3 main.lFDfigPOFq
		$a_01_2 = {6d 61 69 6e 2e 52 44 46 } //1 main.RDF
		$a_01_3 = {6d 61 69 6e 2e 43 4f 4e 54 45 58 54 } //1 main.CONTEXT
		$a_01_4 = {58 4f 52 4b 65 79 } //1 XORKey
		$a_01_5 = {6d 61 69 6e 2e 49 53 4c 41 64 54 4a 55 4b 4c } //2 main.ISLAdTJUKL
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*2) >=10
 
}