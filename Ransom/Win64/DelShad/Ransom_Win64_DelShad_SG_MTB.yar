
rule Ransom_Win64_DelShad_SG_MTB{
	meta:
		description = "Ransom:Win64/DelShad.SG!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {44 61 74 61 5c 72 69 63 6b 2e 70 6e 67 } //1 Data\rick.png
		$a_01_1 = {2f 63 20 76 73 73 61 64 6d 69 6e 2e 65 78 65 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //2 /c vssadmin.exe delete shadows /all /quiet
		$a_01_2 = {42 43 72 79 70 74 45 6e 63 72 79 70 74 } //1 BCryptEncrypt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=3
 
}