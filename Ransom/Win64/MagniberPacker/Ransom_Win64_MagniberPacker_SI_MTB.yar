
rule Ransom_Win64_MagniberPacker_SI_MTB{
	meta:
		description = "Ransom:Win64/MagniberPacker.SI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {99 4a 3e 2b 01 f7 91 ?? ?? ?? ?? bd ?? ?? ?? ?? ec b9 ?? ?? ?? ?? 36 38 27 } //1
		$a_03_1 = {91 81 f9 53 5d bd 4e d1 2f b4 ?? 66 29 1f e7 ?? ae 8c ae ?? ?? ?? ?? 32 2e } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}