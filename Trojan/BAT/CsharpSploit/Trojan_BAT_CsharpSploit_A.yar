
rule Trojan_BAT_CsharpSploit_A{
	meta:
		description = "Trojan:BAT/CsharpSploit.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 73 68 61 72 70 5f 73 74 72 65 61 6d 65 72 2e 6d 73 31 37 5f 31 30 } //2 csharp_streamer.ms17_10
		$a_01_1 = {53 68 61 72 70 53 70 6c 6f 69 74 52 65 73 75 6c 74 4c 69 73 74 } //1 SharpSploitResultList
		$a_01_2 = {42 75 69 6c 64 49 6d 70 6f 72 74 41 64 64 72 65 73 73 54 61 62 6c 65 } //1 BuildImportAddressTable
		$a_01_3 = {4c 6f 67 69 6e 41 6e 6f 6e 79 6d 6f 75 73 41 73 79 6e 63 } //1 LoginAnonymousAsync
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}