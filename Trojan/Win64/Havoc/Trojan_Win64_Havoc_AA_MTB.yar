
rule Trojan_Win64_Havoc_AA_MTB{
	meta:
		description = "Trojan:Win64/Havoc.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {64 65 6d 6f 6e 2e 78 36 34 2e 64 6c 6c 00 44 6c 6c 4d 61 69 6e } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}