
rule Trojan_BAT_Spy_SCC_MTB{
	meta:
		description = "Trojan:BAT/Spy.SCC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {24 36 38 39 65 36 62 32 62 2d 35 63 33 39 2d 34 38 32 32 2d 61 34 62 65 2d 62 62 37 66 66 64 36 35 32 65 37 37 } //10 $689e6b2b-5c39-4822-a4be-bb7ffd652e77
		$a_01_1 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_01_2 = {47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 } //1 GetTypeFromHandle
		$a_01_3 = {43 75 72 72 65 6e 74 44 6f 6d 61 69 6e 5f 41 73 73 65 6d 62 6c 79 52 65 73 6f 6c 76 65 } //1 CurrentDomain_AssemblyResolve
		$a_01_4 = {4e 65 77 74 6f 6e 73 6f 66 74 } //1 Newtonsoft
		$a_01_5 = {44 65 63 6f 6d 70 72 65 73 73 } //1 Decompress
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}