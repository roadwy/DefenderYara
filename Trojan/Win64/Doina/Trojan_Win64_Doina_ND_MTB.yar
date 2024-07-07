
rule Trojan_Win64_Doina_ND_MTB{
	meta:
		description = "Trojan:Win64/Doina.ND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {78 0f 3b 35 60 af 02 00 73 07 b8 90 01 04 eb 02 33 c0 85 c0 75 33 41 c6 41 38 90 01 01 41 83 61 34 90 00 } //5
		$a_01_1 = {44 65 6c 65 74 65 46 69 6c 65 57 } //1 DeleteFileW
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}