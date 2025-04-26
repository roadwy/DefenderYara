
rule Trojan_Win64_RootTeam_RDA_MTB{
	meta:
		description = "Trojan:Win64/RootTeam.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {e9 26 00 00 00 c8 25 92 29 7f 21 7e 0c 1e a5 0b 57 ae e9 a8 8a 39 1a d8 ea 82 45 89 83 f3 77 a2 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}