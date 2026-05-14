
rule Trojan_Win64_Amadey_YB_MTB{
	meta:
		description = "Trojan:Win64/Amadey.YB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 50 ff 83 e2 1e 0f b6 54 14 50 30 54 08 f9 89 c2 83 e2 1f 0f b6 54 14 50 30 54 08 fa 48 83 c0 02 48 83 f8 27 75 d9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}