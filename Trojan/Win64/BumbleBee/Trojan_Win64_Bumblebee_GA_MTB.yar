
rule Trojan_Win64_Bumblebee_GA_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {42 8b 0c 30 33 4a 60 48 8b 83 80 00 00 00 41 89 0c 06 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}