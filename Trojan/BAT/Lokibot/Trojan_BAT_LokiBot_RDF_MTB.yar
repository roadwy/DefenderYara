
rule Trojan_BAT_LokiBot_RDF_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.RDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {2a 72 02 7b ?? ?? ?? ?? 04 02 7b ?? ?? ?? ?? 6f 17 01 00 0a 5d 6f 18 01 00 0a 03 61 d2 2a } //2
		$a_01_1 = {47 65 74 50 72 6f 63 41 64 64 72 65 73 73 } //1 GetProcAddress
		$a_01_2 = {4c 6f 61 64 4c 69 62 72 61 72 79 } //1 LoadLibrary
		$a_01_3 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}