
rule Ransom_Win64_PenterWare_GS_MTB{
	meta:
		description = "Ransom:Win64/PenterWare.GS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {44 0f b6 0c 0e ff c2 44 0f b6 d2 46 8b 1c 90 44 01 df 44 0f b6 e7 46 8b 2c a0 46 89 2c 90 46 89 1c a0 47 8d 14 2b 45 0f b6 d2 46 33 0c 90 44 88 0c 0b 48 ff c1 49 39 c8 } //1
		$a_01_1 = {76 73 73 61 64 6d 69 6e 2e 65 78 65 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 20 2f 3f } //1 vssadmin.exe delete shadows /all /quiet /?
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}