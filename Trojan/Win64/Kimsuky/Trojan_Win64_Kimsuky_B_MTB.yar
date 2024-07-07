
rule Trojan_Win64_Kimsuky_B_MTB{
	meta:
		description = "Trojan:Win64/Kimsuky.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 0f b7 4c 6c 90 01 01 66 44 33 0c 70 48 8b 4f 10 48 8b 57 18 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}