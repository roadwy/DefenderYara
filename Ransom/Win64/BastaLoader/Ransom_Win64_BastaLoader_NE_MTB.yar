
rule Ransom_Win64_BastaLoader_NE_MTB{
	meta:
		description = "Ransom:Win64/BastaLoader.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 3a 3a 9c 59 ?? ?? ?? ?? 44 ec 33 4f ?? 43 43 eb ?? 34 ?? ac 1b 44 6c ?? c7 47 } //1
		$a_03_1 = {31 3a 3a 9c 59 ?? ?? ?? ?? ec d3 c7 42 63 43 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}