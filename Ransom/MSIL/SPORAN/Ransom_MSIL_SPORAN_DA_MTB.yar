
rule Ransom_MSIL_SPORAN_DA_MTB{
	meta:
		description = "Ransom:MSIL/SPORAN.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {56 69 61 67 72 61 5c 64 6f 74 6e 65 74 66 78 33 35 73 65 74 75 70 5c 6f 62 6a 5c 78 38 36 5c 44 65 62 75 67 5c 64 6f 74 6e 65 74 66 78 33 35 73 65 74 75 70 2e 70 64 62 } //1 Viagra\dotnetfx35setup\obj\x86\Debug\dotnetfx35setup.pdb
		$a_81_1 = {2e 48 54 4d 4c 20 69 6e 20 65 76 65 72 79 20 66 6f 6c 64 65 72 2c 20 66 6f 72 20 69 6e 73 74 72 75 63 74 69 6f 6e 73 20 6f 6e 20 68 6f 77 20 74 6f 20 67 65 74 20 79 6f 75 72 20 66 69 6c 65 73 20 62 61 63 6b 2e } //1 .HTML in every folder, for instructions on how to get your files back.
		$a_81_2 = {76 73 73 61 64 6d 69 6e 2e 65 78 65 20 44 65 6c 65 74 65 20 53 68 61 64 6f 77 73 20 2f 41 6c 6c 20 2f 51 75 69 65 74 } //1 vssadmin.exe Delete Shadows /All /Quiet
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}