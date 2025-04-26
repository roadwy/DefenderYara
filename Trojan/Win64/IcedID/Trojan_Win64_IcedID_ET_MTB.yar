
rule Trojan_Win64_IcedID_ET_MTB{
	meta:
		description = "Trojan:Win64/IcedID.ET!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {49 c7 c4 9c 07 00 00 48 93 48 13 ec 48 81 ee 4b 19 00 00 c8 0e 00 00 cd a0 c3 88 4c 24 08 48 83 ec 18 e9 fd 00 00 00 48 83 c4 18 c3 e6 71 } //4
		$a_01_1 = {44 66 67 6a 6b 67 73 64 66 64 67 68 6a 66 73 61 } //1 Dfgjkgsdfdghjfsa
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}