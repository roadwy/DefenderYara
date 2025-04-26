
rule Trojan_Win64_Discord_ARA_MTB{
	meta:
		description = "Trojan:Win64/Discord.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {72 65 70 6f 72 74 68 74 74 70 73 3a 2f 2f 61 72 73 65 6e 69 74 65 2e 73 75 2f 6c 6f 67 67 65 72 2f } //2 reporthttps://arsenite.su/logger/
		$a_01_1 = {5c 69 6e 6a 65 63 74 6f 72 2e 70 64 62 } //2 \injector.pdb
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}