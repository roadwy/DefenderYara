
rule Trojan_Win64_EncSivisLoader_A{
	meta:
		description = "Trojan:Win64/EncSivisLoader.A,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {66 69 6c 65 53 59 53 } //1 fileSYS
		$a_01_1 = {66 69 6c 65 50 61 79 6c 6f 61 64 } //1 filePayload
		$a_01_2 = {47 5a 69 70 53 74 72 65 61 6d } //1 GZipStream
		$a_01_3 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //1 get_CurrentDomain
		$a_01_4 = {4f 6e 52 65 73 6f 6c 76 65 41 73 73 65 6d 62 6c 79 } //1 OnResolveAssembly
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}