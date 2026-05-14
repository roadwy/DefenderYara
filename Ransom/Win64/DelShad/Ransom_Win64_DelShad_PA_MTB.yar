
rule Ransom_Win64_DelShad_PA_MTB{
	meta:
		description = "Ransom:Win64/DelShad.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 79 73 74 65 6d 20 69 6e 74 65 67 72 69 74 79 20 64 65 73 74 72 6f 79 65 64 } //1 System integrity destroyed
		$a_01_1 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 65 78 70 6c 6f 72 65 72 2e 65 78 65 } //1 taskkill /f /im explorer.exe
		$a_01_2 = {63 6d 64 20 2f 63 20 76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //3 cmd /c vssadmin delete shadows /all /quiet
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*3) >=5
 
}