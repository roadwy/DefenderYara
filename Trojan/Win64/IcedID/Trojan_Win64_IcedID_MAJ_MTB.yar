
rule Trojan_Win64_IcedID_MAJ_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {42 6a 68 61 73 79 75 69 6a 6b 61 73 } //1 Bjhasyuijkas
		$a_01_1 = {42 79 41 73 64 51 } //1 ByAsdQ
		$a_01_2 = {46 65 58 53 55 54 71 44 } //1 FeXSUTqD
		$a_01_3 = {49 35 56 57 61 56 6a 32 67 } //1 I5VWaVj2g
		$a_01_4 = {4e 48 35 6e 4c 43 } //1 NH5nLC
		$a_01_5 = {50 43 74 6b 47 62 51 42 39 } //1 PCtkGbQB9
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}