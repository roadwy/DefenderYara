
rule Trojan_Linux_Sliver_A_MTB{
	meta:
		description = "Trojan:Linux/Sliver.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {73 6c 69 76 65 72 70 62 2f 73 6c 69 76 65 72 2e 70 72 6f 74 6f } //2 sliverpb/sliver.proto
		$a_00_1 = {2f 62 69 73 68 6f 70 66 6f 78 2f 73 6c 69 76 65 72 2f 70 72 6f 74 6f 62 75 66 2f 73 6c 69 76 65 72 70 62 62 } //1 /bishopfox/sliver/protobuf/sliverpbb
		$a_00_2 = {73 6c 69 76 65 72 70 62 2e 50 77 64 } //1 sliverpb.Pwd
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}