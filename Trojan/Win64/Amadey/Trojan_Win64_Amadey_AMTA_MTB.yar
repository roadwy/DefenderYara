
rule Trojan_Win64_Amadey_AMTA_MTB{
	meta:
		description = "Trojan:Win64/Amadey.AMTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 03 c8 0f b6 01 41 88 04 19 44 88 11 41 0f b6 0c 19 49 03 ca 0f b6 c1 0f b6 4c 04 30 42 32 0c 07 41 88 08 49 ff c0 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}