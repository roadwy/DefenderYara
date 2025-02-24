
rule Trojan_Win64_Amadey_AUJ_MTB{
	meta:
		description = "Trojan:Win64/Amadey.AUJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {eb 08 0f 94 5d 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}