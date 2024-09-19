
rule Trojan_Win64_NimLoader_A_MTB{
	meta:
		description = "Trojan:Win64/NimLoader.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b 44 24 ?? 49 8b 0c f7 4c 89 f2 48 d3 fa 30 54 18 ?? 48 83 fe } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}