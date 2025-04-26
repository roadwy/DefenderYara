
rule Ransom_Win64_MagniberPacker_SE_MTB{
	meta:
		description = "Ransom:Win64/MagniberPacker.SE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {ba 4b eb 25 cf 32 9d ?? ?? ?? ?? ?? 15 ?? ?? ?? ?? 31 0a f7 3f 22 61 ?? dc 5e ?? 10 9c d8 ?? ?? ?? ?? 02 85 ?? ?? ?? ?? 2b 23 a2 } //1
		$a_00_1 = {42 4d 77 55 57 68 79 54 71 68 77 73 } //1 BMwUWhyTqhws
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}