
rule Trojan_Win64_Petwosel_DA_MTB{
	meta:
		description = "Trojan:Win64/Petwosel.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {46 0f be 14 0a 45 8d 5a bf 44 89 d7 83 cf 20 41 80 fb 1a 41 0f 43 fa 44 31 c7 44 69 c7 8d 05 b4 00 49 83 c1 02 4c 39 c9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}