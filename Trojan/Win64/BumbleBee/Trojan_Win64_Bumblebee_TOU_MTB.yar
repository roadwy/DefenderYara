
rule Trojan_Win64_Bumblebee_TOU_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.TOU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {49 83 e7 69 49 81 c6 34 a8 45 41 48 83 c6 55 49 83 f5 99 48 81 6c 24 40 01 00 00 00 0f 85 de ff ff ff } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}